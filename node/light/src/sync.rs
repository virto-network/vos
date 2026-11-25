//! Sync (`light-node.md` §3.2): each local actor instance is one scope, a
//! merkle-crdt DAG whose nodes the light node's author key signs, each a
//! batch of operations. An operation is a merge handler's call with the
//! time and seed of the device that issued it, and the release of its
//! actor that device ran, so every device that applies the node runs the
//! handler again and writes the same entries (`vos_abi::merge`).
//!
//! Applying a node ([`apply_node`]) writes beside its operations' runs:
//! its Lamport clock, which orders the merge fields' entries; and its
//! author's cutoff where it equivocates, from which the merge fields'
//! reads filter the author. Each operation then runs, or is kept in its
//! scope's rows without running:
//!
//! - **held** ([`Hold`]) while this device cannot run it yet: a kind this
//!   build does not know, a later release of its actor than the one
//!   installed, or a run that faulted here. A held operation runs at the
//!   next replay that can run it (an install replays its instance's), so
//!   devices on different releases converge once they update;
//! - **quarantined** ([`Quarantine`]) when it is invalid, never applied
//!   and reported with its author: a frame no device records, a run that
//!   fails where the issuing device's was done, or an author the device
//!   set removed, already cut off at or before its number. An
//!   equivocation's operations still apply, filtered at read: which fork
//!   came first differs between devices, and applying both keeps their
//!   reads alike.

use std::collections::BTreeMap;

use blake2::Blake2b;
use blake2::digest::Digest;
use blake2::digest::consts::U32;
use fjall::{Keyspace, OwnedWriteBatch};
use merkle_crdt::{
    Author, Changes, Decode, Encode, Event, FjallError, FjallStore, Loaded, Rows, Store,
};
use vos_abi::abi::Failure;
use vos_abi::ids::{InstanceId, MethodId};
use vos_abi::keys;
use vos_abi::merge::{Cutoff, Origin};
use vos_abi::records::{stored, unstored};

/// The hash a scope's nodes are named by: BLAKE2b-256.
#[derive(Debug)]
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
/// and seed, which every device that applies it runs on, and the release
/// of its actor the issuing device ran it on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub release: u32,
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
        self.release.encode_to(buf);
        self.method.0.encode_to(buf);
        self.arguments.encode_to(buf);
        self.time.encode_to(buf);
        self.seed.encode_to(buf);
    }
}

impl Decode for Call {
    fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
        Some(Call {
            release: u32::decode_from(buf, pos)?,
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

/// Why an operation is held: it runs once this device can run it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, vos_abi::Encode, vos_abi::Decode)]
#[repr(u8)]
pub enum Hold {
    /// A kind this build does not know: it runs after the app's update.
    #[codec(index = 0)]
    Kind = 0,
    /// A release of its actor after the one installed here: it runs once
    /// that release is installed.
    #[codec(index = 1)]
    Release = 1,
    /// Its run faulted here, the device's failure and not the operation's:
    /// it runs again at the next replay.
    #[codec(index = 2)]
    Fault = 2,
}

/// Why an operation is quarantined: it is never applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, vos_abi::Encode, vos_abi::Decode)]
pub enum Quarantine {
    /// Its frame is one no device records: arguments past
    /// [`crate::MAX_ARGUMENTS`].
    #[codec(index = 0)]
    Invalid,
    /// Its run failed so, under a release this device runs, where the
    /// issuing device records an operation only when its run is done: the
    /// author wrote garbage, or ran another program under that release.
    #[codec(index = 1)]
    Failed(Failure),
    /// Its author was removed, cut off at or before its sequence number,
    /// past the frontier the device set gives a removed device.
    #[codec(index = 2)]
    CutOff,
}

/// An operation kept in its scope's rows without being applied: its
/// node's CID, its origin, the operation, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kept<W> {
    pub cid: Cid,
    pub origin: Origin,
    pub op: Op,
    pub why: W,
}

/// An operation held for a later run.
pub type Held = Kept<Hold>;

/// An operation quarantined.
pub type Quarantined = Kept<Quarantine>;

impl<W: Copy + vos_abi::Encode + vos_abi::Decode> Kept<W> {
    /// The kept operation of the row `key`, `value`, under `prefix`
    /// ([`keys::held_prefix`] or [`keys::quarantined_op_prefix`]).
    pub(crate) fn read(prefix: &[u8], key: &[u8], value: &[u8]) -> Result<Self, CorruptRow> {
        let rest = key.strip_prefix(prefix).ok_or(CorruptRow)?;
        let (cid, _index) = rest.split_first_chunk::<32>().ok_or(CorruptRow)?;
        let (origin, op, why) = unstored(value)
            .and_then(<(Origin, Vec<u8>, W) as vos_abi::Decode>::decode_exact)
            .ok_or(CorruptRow)?;
        Ok(Self {
            cid: merkle_crdt::Cid(*cid),
            origin,
            op: Op::decode(&op).ok_or(CorruptRow)?,
            why,
        })
    }

    fn row(&self) -> Vec<u8> {
        stored(&vos_abi::Encode::encode(&(
            self.origin,
            self.op.encode(),
            self.why,
        )))
    }
}

/// The name of local instance `instance`'s scope, from which its id
/// derives with the key archive's naming secret
/// ([`crate::group::archive::scope_id`]): devices sharing the archive sync
/// an instance's scope with each other.
pub fn scope_name(instance: InstanceId) -> [u8; 4] {
    instance.0.to_be_bytes()
}

/// A row the light node wrote that does not read as written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorruptRow;

/// The value of a stored row of a light node's, as it wrote it.
fn read<T: vos_abi::Decode>(rows: &mut dyn Rows, key: &[u8]) -> Result<Option<T>, CorruptRow> {
    rows.read(key)
        .map(|bytes| unstored(&bytes).and_then(T::decode_exact).ok_or(CorruptRow))
        .transpose()
}

fn write(rows: &mut dyn Rows, key: &[u8], value: &impl vos_abi::Encode) {
    rows.write(key, Some(&stored(&value.encode())));
}

/// Hold `kept` in `instance`'s scope's rows, for a later run.
pub fn hold(instance: InstanceId, kept: &Held, rows: &mut dyn Rows) {
    let key = keys::held(instance, &kept.cid.0, kept.origin.index);
    rows.write(&key, Some(&kept.row()));
}

/// Quarantine `kept` in `instance`'s scope's rows: never applied.
pub fn quarantine(instance: InstanceId, kept: &Quarantined, rows: &mut dyn Rows) {
    let key = keys::quarantined_op(instance, &kept.cid.0, kept.origin.index);
    rows.write(&key, Some(&kept.row()));
}

/// `author`'s cutoff in `instance`'s scope, if it has one.
pub(crate) fn cutoff(
    rows: &mut dyn Rows,
    instance: InstanceId,
    author: &[u8; 32],
) -> Result<Option<Cutoff>, CorruptRow> {
    read::<Cutoff>(rows, &keys::cutoff(instance, author))
}

/// `author`'s cutoff in `instance`'s scope as the device set removed it,
/// if it did ([`keys::removed`]).
pub(crate) fn removed(
    rows: &mut dyn Rows,
    instance: InstanceId,
    author: &[u8; 32],
) -> Result<Option<Cutoff>, CorruptRow> {
    read::<Cutoff>(rows, &keys::removed(instance, author))
}

/// Apply `event`, a node of `instance`'s scope, through `rows`: its Lamport
/// clock, one more than its parents' greatest; its author's cutoff from its
/// sequence number where it equivocates; then each operation in order, by
/// `run` with its node's CID and its origin, which runs it, holds it or
/// quarantines it.
pub fn apply_node<E: From<CorruptRow>>(
    instance: InstanceId,
    event: &Event<'_, Blake2b256, Ops>,
    rows: &mut dyn Rows,
    mut run: impl FnMut(&Cid, &Origin, &Op, &mut dyn Rows) -> Result<(), E>,
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
        let cutoff = cutoff(rows, instance, &author)?;
        if cutoff.is_none_or(|cutoff| event.seq < cutoff.0) {
            write(rows, &keys::cutoff(instance, &author), &Cutoff(event.seq));
        }
    }
    for (index, op) in event.ops.iter().enumerate() {
        let origin = Origin {
            author,
            seq: event.seq,
            lamport,
            index: u32::try_from(index).map_err(|_| CorruptRow)?,
        };
        run(event.cid, &origin, op, rows)?;
    }
    Ok(())
}

/// A scope's store: its keyspaces in the light node's database, its rows
/// the local agent's, and the light node's own writes an operation stages
/// ([`ScopeStore::stage`]), which the scope's next commit carries in its
/// batch.
pub(crate) struct ScopeStore {
    inner: FjallStore,
    staged: Vec<(Keyspace, Vec<u8>, Option<Vec<u8>>)>,
}

impl ScopeStore {
    pub(crate) fn new(inner: FjallStore) -> Self {
        Self {
            inner,
            staged: Vec::new(),
        }
    }

    /// Stage `value` under `key` in `keyspace` for the next commit; `None`
    /// deletes it.
    pub(crate) fn stage(&mut self, keyspace: &Keyspace, key: &[u8], value: Option<Vec<u8>>) {
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

    fn held(&self, cid: &Cid) -> Result<Option<Vec<u8>>, FjallError> {
        self.inner.held(cid)
    }

    fn authored(&self, author: &Author, seq: u64) -> Result<Option<Cid>, FjallError> {
        self.inner.authored(author, seq)
    }

    fn is_authored(&self, author: &Author, seq: u64, cid: &Cid) -> Result<bool, FjallError> {
        self.inner.is_authored(author, seq, cid)
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
                    match value {
                        Some(value) => batch.insert(&keyspace, key, value),
                        None => batch.remove(&keyspace, key),
                    }
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
