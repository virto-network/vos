//! The light node (`light-node.md` §2.1): one local agent, the default
//! agent's program, run on the interpreter over the light node's own store,
//! with no log. Each operation runs the agent program and is committed in
//! one batch: an install (a batch of one install, as a node's install); a
//! call, a merge handler's operation (the merge entry, `Work::Merge`),
//! recorded as a node of its instance's scope signed by the store's author
//! key ([`crate::sync`]); a peer's nodes, ingested, each operation run
//! through the same entry; and, writing nothing, a query. No Raft, no
//! leader, no sessions, no sweeps; and no accumulate run: the light node
//! applies an entry's work result itself, an install's by the code a
//! node's accumulate runs (`vos_wire::apply`), a merge's by writing its
//! rows.
//!
//! A peer's operation the light node cannot run yet is held, and one that
//! is invalid quarantined ([`crate::sync`]); an install replays its
//! instance's held operations. Before an operation that adds data (an
//! install, a call, an ingest, a replay) the light node asks the disk for
//! room past its reserve ([`RESERVE_BYTES`]), and refuses it with
//! nothing written when there is none ([`Error::Full`]): the store stops
//! growing before the disk fills, sync pauses, and both resume once room
//! is freed.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::Bound;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use merkle_crdt::{
    Apply, Author, Event, FjallError, FjallStore, Ingested, Outgoing, Replica, Rows,
};
use vos_abi::abi::Failure;
use vos_abi::abi::cap::Target;
use vos_abi::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_abi::merge::{Cutoff, Origin};
use vos_abi::records::{Installed, stored, unstored};
use vos_abi::result::{Outcome, Run, Step, split_output};
use vos_abi::{Decode, Encode, SpaceId, WindowClock, keys};
use vos_exec::{Fault, Machines, ProgramStore, StateReader, decode, panic_message, value_window};
use vos_pvm::PvmBackend;
use vos_pvm::pool::{MachinePool, OuterMachines, PoolError};
use vos_wire::apply::{Host, apply};
use vos_wire::batch::{Admin, Batch, Input, Merge, Query, Work};
use vos_wire::defaults;

use crate::release::Package;
use crate::store::{Applying, CACHE_BYTES, Operation, Snapshot, Store, StoreError};
use crate::sync::{
    self, Blake2b256, Call, CorruptRow, Held, Hold, Kept, Mirrored, Op, Ops, Quarantine,
    Quarantined, ScopeStore,
};

/// The local agent, the light node's one: its id as the agent program
/// sees it.
pub const LOCAL: AgentId = AgentId(1);

/// The most bytes of arguments a call takes: its node, sealed with its
/// writer's view and `seen` positions, fits one envelope
/// ([`crate::sealed::MAX_BODY`]) with room for its parents. Larger objects
/// are chunked by the actor, an operation a chunk.
pub const MAX_ARGUMENTS: usize = 48 << 10;

/// A local node sealed for its push: the epoch it was sealed under, and
/// the envelope, sent as it is until it is taken or refused for its epoch.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Queued {
    pub epoch: u64,
    pub envelope: Vec<u8>,
}

/// The disk room the light node keeps free by default: an operation that
/// adds data is refused below it, leaving room for what removes data or
/// keeps the device in its group.
pub const RESERVE_BYTES: u64 = 64 << 20;

/// How the light node runs: refine's gas for one run is
/// `defaults::REFINE_GAS`, the store's block cache [`CACHE_BYTES`], and an
/// operation that adds data is refused ([`Error::Full`]) below
/// [`RESERVE_BYTES`] of room.
#[derive(Clone, Debug)]
pub struct Config {
    /// Where the room is read.
    pub disk: Disk,
}

impl Default for Config {
    fn default() -> Self {
        Self { disk: Disk::System }
    }
}

/// Where the light node reads the room left on its store's disk.
#[derive(Clone)]
pub enum Disk {
    /// The filesystem the store is on, asked before each operation that
    /// adds data.
    System,
    /// The bytes free a probe answers: a test's disk, filled and freed at
    /// will.
    Probe(Arc<dyn Fn() -> u64 + Send + Sync>),
}

impl std::fmt::Debug for Disk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Disk::System => "System",
            Disk::Probe(_) => "Probe",
        })
    }
}

impl Disk {
    /// The bytes free to an unprivileged writer under `dir`.
    fn free(&self, dir: &Path) -> Result<u64, Error> {
        match self {
            Disk::System => available(dir).map_err(|error| Error::Store(error.into())),
            Disk::Probe(probe) => Ok(probe()),
        }
    }
}

/// The bytes the filesystem under `dir` gives an unprivileged writer.
#[cfg(unix)]
fn available(dir: &Path) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt as _;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: `path` is a NUL-terminated string, and `stat` a zeroed
    // `statvfs` the call writes within.
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so it filled `stat`.
    let stat = unsafe { stat.assume_init() };
    #[allow(clippy::unnecessary_cast)]
    Ok((stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64))
}

#[cfg(not(unix))]
fn available(_: &Path) -> std::io::Result<u64> {
    Ok(u64::MAX)
}

/// Rows an operation writes (`Some`) or deletes (`None`).
type Written = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// A scope's replica, its nodes in the light node's store.
type Scope = Replica<Blake2b256, Ops, ScopeStore>;

/// A scope's failure: its store's, or a stored node that is missing or
/// does not validate.
pub type ScopeError = merkle_crdt::Error<FjallError>;

/// Why an operation produced nothing.
#[derive(Debug)]
pub enum Error {
    /// The store failed: nothing of the operation was written.
    Store(StoreError),
    /// A scope's store failed, or holds a node that does not validate:
    /// nothing of the operation was written.
    Scope(ScopeError),
    /// The agent program failed, or the run did: nothing was written.
    Fault(Fault),
    /// The agent program refused the operation, before running it.
    Refused,
    /// A package whose programs are not its derivation's, or of release 0,
    /// which no release is.
    Package,
    /// A package another transpiler's version derived: its programs are
    /// not the ones this light node's release names.
    Transpiler(u32),
    /// The agent program's work result does not apply to the state it was
    /// refined on: the agent program's fault.
    NotApplied,
    /// A scope of an instance not installed here: no handler could run its
    /// nodes.
    NotInstalled,
    /// A call's arguments past [`MAX_ARGUMENTS`]: nothing was recorded.
    TooLarge,
    /// A package of a release before the one installed, or of the same
    /// release and another program: nothing was installed.
    Release { installed: u32 },
    /// The disk has less room than the light node keeps free: nothing was
    /// written. It succeeds again once room is freed.
    Full { free: u64 },
}

impl From<StoreError> for Error {
    fn from(error: StoreError) -> Self {
        Error::Store(error)
    }
}

impl From<Fault> for Error {
    fn from(fault: Fault) -> Self {
        Error::Fault(fault)
    }
}

impl From<FjallError> for Error {
    fn from(error: FjallError) -> Self {
        Error::Scope(merkle_crdt::Error::Store(error))
    }
}

impl From<CorruptRow> for Error {
    fn from(_: CorruptRow) -> Self {
        Error::Fault(Fault::Invariant("a scope's row does not read".into()))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Store(error) => error.fmt(f),
            Error::Scope(error) => error.fmt(f),
            Error::Fault(fault) => f.write_str(fault.message()),
            Error::Refused => f.write_str("the agent refused the operation"),
            Error::Package => {
                f.write_str("the package's programs are not its derivation's, or its release is 0")
            }
            Error::Transpiler(version) => write!(
                f,
                "the package is transpiler {version}'s, not {}'s",
                crate::release::TRANSPILER
            ),
            Error::NotApplied => f.write_str("the operation's result does not apply"),
            Error::NotInstalled => f.write_str("the instance is not installed"),
            Error::TooLarge => write!(f, "a call's arguments past {MAX_ARGUMENTS} bytes"),
            Error::Release { installed } => write!(
                f,
                "the package's release is before release {installed}, installed, or is \
                 another program under it"
            ),
            Error::Full { free } => write!(
                f,
                "the disk has {free} bytes free, less than the light node keeps: free room"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// A scope's failure as the light node's, the CRDT's error its own.
fn scope_error(error: merkle_crdt::Error<FjallError, Halt>) -> Halt {
    match error {
        merkle_crdt::Error::Apply(halt) => halt,
        merkle_crdt::Error::Store(error) => {
            Halt::Error(Error::Scope(merkle_crdt::Error::Store(error)))
        }
        merkle_crdt::Error::Corrupt => Halt::Error(Error::Scope(merkle_crdt::Error::Corrupt)),
        merkle_crdt::Error::Stalled => Halt::Error(Error::Scope(merkle_crdt::Error::Stalled)),
        merkle_crdt::Error::Disordered => Halt::Error(Error::Scope(merkle_crdt::Error::Disordered)),
        merkle_crdt::Error::Source(never) => match never {},
    }
}

/// Why applying a node stopped: a local operation its handler declined,
/// whose outcome the caller gets with nothing written, or an error.
#[derive(Debug)]
enum Halt {
    Declined(Outcome),
    Error(Error),
}

impl From<Error> for Halt {
    fn from(error: Error) -> Self {
        Halt::Error(error)
    }
}

impl From<CorruptRow> for Halt {
    fn from(error: CorruptRow) -> Self {
        Halt::Error(error.into())
    }
}

/// The light node: its store, the agent program's machines, its author
/// key, and its scopes, behind one lock that runs its write operations one
/// at a time.
pub struct Light {
    store: Store,
    dir: PathBuf,
    machines: Machines,
    config: Config,
    key: SigningKey,
    writing: Mutex<BTreeMap<InstanceId, Scope>>,
}

impl Light {
    /// Open the light node at `dir`, its agent program `agent` (the
    /// default agent, linked: a release artifact), and every program
    /// installed in its store pooled.
    pub fn open(dir: &Path, agent: &[u8], config: Config) -> Result<Self, Error> {
        let store = Store::open(dir, CACHE_BYTES)?;
        let unloadable = |error| Error::Fault(Fault::Agent(format!("{error:?}")));
        // One operation runs at a time: one machine kept idle.
        let program = OuterMachines::with_idle_limit(agent, PvmBackend::ForceInterpreter, 1)
            .map_err(|error| {
                Error::Fault(Fault::Agent(
                    match error {
                        PoolError::ServiceTooBig => {
                            "the agent is past the service-code bound (W_C)"
                        }
                        PoolError::InvalidProgram => "the agent is not a standard program",
                        PoolError::Backend => "the agent's backend failed",
                    }
                    .into(),
                ))
            })?;
        // A phone's pool: few idle machines, as one operation runs at a time.
        let pool = Arc::new(MachinePool::with_idle_limits(8, 2));
        for (_, program) in store.programs()? {
            pool.install(&program).map_err(unloadable)?;
        }
        let machines = Machines {
            program: Arc::new(program),
            pool,
            programs: Arc::new(store.clone()) as Arc<dyn ProgramStore>,
        };
        let key = SigningKey::from_bytes(&*store.author()?);
        Ok(Self {
            store,
            dir: dir.to_path_buf(),
            machines,
            config,
            key,
            writing: Mutex::new(BTreeMap::new()),
        })
    }

    /// The light node's store.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The author its scopes' nodes are signed by: its store's, drawn
    /// when the store was made, so a new install or a restore is a new
    /// author.
    pub fn author(&self) -> Author {
        Author::from(&self.key)
    }

    /// The device's sync key: its scopes' author, so a reader checks each
    /// node's author against the device set, and the client key of its
    /// calls at the personal agent, its votes and its evidence.
    pub fn sync_key(&self) -> &SigningKey {
        &self.key
    }

    /// The node `cid` of `instance`'s scope, if the scope holds it.
    pub fn node(&self, instance: InstanceId, cid: &sync::Cid) -> Result<Option<Vec<u8>>, Error> {
        let mut writing = self.writing();
        let scope = self.scope(&mut writing, instance)?;
        Ok(merkle_crdt::Store::node(scope.store(), cid)?)
    }

    /// The release installed at `instance`, if one is.
    pub fn release(&self, instance: InstanceId) -> Result<Option<u32>, Error> {
        release(&self.store.snapshot(), instance)
    }

    /// The instances installed, in order.
    pub fn instances(&self) -> Result<Vec<InstanceId>, Error> {
        let snapshot = self.store.snapshot();
        let prefix = keys::installed_prefix();
        StateReader::rows(&snapshot, &prefix, None)
            .map(|(key, _)| {
                let id = key
                    .get(prefix.len()..)
                    .and_then(|id| <[u8; 4]>::try_from(id).ok())
                    .ok_or(CorruptRow)?;
                Ok(InstanceId(u32::from_be_bytes(id)))
            })
            .collect()
    }

    /// Install `package` as `instance`, its roles `roles`: its programs
    /// checked against its derivation and pooled, the install run as a
    /// node's, and its programs, its rows and its release committed in one
    /// batch; then the instance's held operations replayed ([`Light::replay`]),
    /// whose failure (a full disk, the store's) leaves them held for the
    /// next replay and the install standing. A package of a release before
    /// the installed one, or of that release and another program, is
    /// refused. The install's outcome; a failed install stores nothing but
    /// the operation's mark.
    pub fn install(
        &self,
        instance: InstanceId,
        package: &Package,
        roles: Vec<(Vec<u8>, u8)>,
    ) -> Result<Outcome, Error> {
        if package.release == 0 {
            return Err(Error::Package);
        }
        if package.derivation.transpiler != crate::release::TRANSPILER {
            return Err(Error::Transpiler(package.derivation.transpiler));
        }
        let programs = package.checked().ok_or(Error::Package)?;
        for (_, program) in &programs {
            self.machines
                .pool
                .install(program)
                .map_err(|error| Error::Fault(Fault::Agent(format!("{error:?}"))))?;
        }
        let mut writing = self.writing();
        self.room()?;
        let snapshot = self.store.snapshot();
        if let Some(installed) = release(&snapshot, instance)? {
            let over = snapshot
                .get(&keys::installed(instance))?
                .and_then(|bytes| unstored(&bytes).and_then(Installed::decode_exact))
                .ok_or(CorruptRow)?;
            if package.release < installed
                || (package.release == installed && over.derivation != package.derivation)
            {
                return Err(Error::Release { installed });
            }
        }
        let version = version(&snapshot)?;
        let (time, seed) = self.next(&snapshot)?;
        let work = Work::Batch(Batch {
            version,
            time,
            seed,
            budget: defaults::REFINE_GAS,
            inputs: vec![Input::Admin(Admin::Install {
                instance,
                derivation: package.derivation.clone(),
                roles,
                target: Target::Vos,
                space: SpaceId::NONE,
                clock: WindowClock::DEFAULT,
            })],
        });
        let machines = Machines {
            programs: Arc::new(Installing {
                store: self.store.clone(),
                programs: programs
                    .iter()
                    .map(|(hash, program)| (*hash, program.to_vec()))
                    .collect(),
            }),
            ..self.machines.clone()
        };
        let snapshot = Arc::new(snapshot);
        let output = self.refine(&machines, Arc::clone(&snapshot) as _, &work)?;
        let (outcome, rows) = self.applied(&snapshot, &output)?;
        let mut operation = Operation {
            rows,
            programs: Vec::new(),
            time,
            seed,
        };
        let done = matches!(outcome, Outcome::Done(_));
        if done {
            operation.programs = programs
                .into_iter()
                .map(|(hash, program)| (hash, program.to_vec()))
                .collect();
            operation.rows.insert(
                keys::release(instance),
                Some(stored(&package.release.encode())),
            );
        }
        self.store.commit(operation)?;
        if done {
            // The install stands whatever its replay does: what the replay
            // could not run waits, held, for the next.
            let _ = self.replay_held(&mut writing, instance);
        }
        Ok(outcome)
    }

    /// Call `instance`'s merge handler `method` with `arguments`: an
    /// operation of the light node's author, at its time and seed, run on
    /// the merge entry and recorded as a node of the instance's scope,
    /// signed, its rows and its node committed in one batch. The handler's
    /// outcome; one that is not `Done` records and writes nothing, as for
    /// an instance not installed (`Unknown`).
    pub fn call(
        &self,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> Result<Outcome, Error> {
        if arguments.len() > MAX_ARGUMENTS {
            return Err(Error::TooLarge);
        }
        let mut writing = self.writing();
        let snapshot = self.store.snapshot();
        if snapshot.get(&keys::installed(instance))?.is_none() {
            return Ok(Outcome::failed(Failure::Unknown));
        }
        self.room()?;
        let (time, seed) = self.next(&snapshot)?;
        let ops = vec![Op::Call(Call {
            release: release(&snapshot, instance)?.unwrap_or(0),
            method,
            arguments,
            time,
            seed,
        })];
        let scope = self.scope(&mut writing, instance)?;
        let (meta, key, last) = self.store.last_row(time, &seed);
        scope.store_mut().stage(meta, key, Some(last));
        let mut merging = Merging::new(self, instance, snapshot, true)?;
        let recorded = scope.record(&self.key, ops, &mut merging);
        scope.store_mut().unstage();
        match recorded.map_err(scope_error) {
            Ok(_) => Ok(merging.outcome.unwrap_or(Outcome::Done(Vec::new()))),
            Err(Halt::Declined(outcome)) => Ok(outcome),
            Err(Halt::Error(error)) => Err(error),
        }
    }

    /// Apply nodes of `instance`'s scope a peer or a feed sent, in one
    /// batch: each validated, and each operation of each node run, in
    /// causal order, through the merge entry as the device that issued it
    /// ran it; `cursor`, the feed's position they were read to, stored
    /// with them. An operation this device cannot run yet is held, and an
    /// invalid one, or one whose author the device set removed at or before
    /// its number,
    /// quarantined ([`crate::sync`]); both are kept in the scope's rows and
    /// reported. Refused with nothing written when the disk has no room
    /// ([`Error::Full`]).
    pub fn ingest(
        &self,
        instance: InstanceId,
        nodes: impl IntoIterator<Item = Vec<u8>>,
        cursor: Option<u64>,
    ) -> Result<Ingest, Error> {
        let mut writing = self.writing();
        let scope = self.scope(&mut writing, instance)?;
        self.room()?;
        let snapshot = self.store.snapshot();
        let mut merging = Merging::new(self, instance, snapshot, false)?;
        match scope
            .ingest(nodes, cursor, &mut merging)
            .map_err(scope_error)
        {
            Ok(nodes) => Ok(Ingest {
                nodes,
                held: merging.held,
                quarantined: merging.quarantined,
            }),
            Err(Halt::Declined(_)) => unreachable!("a peer's operation is never declined"),
            Err(Halt::Error(error)) => Err(error),
        }
    }

    /// Run `instance`'s held operations this device can run now, in one
    /// batch: each that runs applied as it would have been at its ingest,
    /// each found invalid, or whose author was cut off since, quarantined,
    /// and the rest held still. An install replays its instance's; a
    /// fault's operations wait for the next replay.
    pub fn replay(&self, instance: InstanceId) -> Result<Replayed, Error> {
        let mut writing = self.writing();
        self.replay_held(&mut writing, instance)
    }

    /// `instance`'s operations held, in their rows' order.
    pub fn held(&self, instance: InstanceId) -> Result<Vec<Held>, Error> {
        self.kept(&keys::held_prefix(instance))
    }

    /// `instance`'s operations quarantined, in their rows' order: what the
    /// chrome names, with each one's author.
    pub fn quarantined(&self, instance: InstanceId) -> Result<Vec<Quarantined>, Error> {
        self.kept(&keys::quarantined_op_prefix(instance))
    }

    /// `author`'s cutoff in `instance`'s scope: its operations at this
    /// sequence number and later are filtered at read, and quarantined
    /// when they arrive after it is known.
    pub fn cutoff(&self, instance: InstanceId, author: &Author) -> Result<Option<u64>, Error> {
        let key = keys::cutoff(instance, &author.0);
        Ok(match self.store.snapshot().get(&key)? {
            Some(bytes) => Some(
                unstored(&bytes)
                    .and_then(Cutoff::decode_exact)
                    .ok_or(CorruptRow)?
                    .0,
            ),
            None => None,
        })
    }

    /// The operations kept under `prefix`.
    fn kept<W: Copy + Encode + Decode>(&self, prefix: &[u8]) -> Result<Vec<Kept<W>>, Error> {
        let snapshot = self.store.snapshot();
        snapshot
            .scan(prefix, None)
            .map(|(key, value)| Ok(Kept::read(prefix, &key, &value)?))
            .collect()
    }

    /// [`Light::replay`], under the write lock `_writing`.
    fn replay_held(
        &self,
        _writing: &mut MutexGuard<'_, BTreeMap<InstanceId, Scope>>,
        instance: InstanceId,
    ) -> Result<Replayed, Error> {
        let held = self.held(instance)?;
        let mut replayed = Replayed::default();
        if held.is_empty() {
            return Ok(replayed);
        }
        self.room()?;
        let snapshot = self.store.snapshot();
        let mut merging = Merging::new(self, instance, snapshot, false)?;
        let snapshot = Arc::clone(&merging.snapshot);
        let mut changes = Written::new();
        for kept in held {
            let mut rows = Staged {
                snapshot: &snapshot,
                written: &mut changes,
            };
            rows.write(&keys::held(instance, &kept.cid.0, kept.origin.index), None);
            let (held, quarantined) = (merging.held.len(), merging.quarantined.len());
            merging
                .run(&kept.cid, &kept.origin, &kept.op, &mut rows)
                .map_err(|halt| match halt {
                    Halt::Error(error) => error,
                    Halt::Declined(_) => unreachable!("a peer's operation is never declined"),
                })?;
            if merging.held.len() > held {
                replayed.held += 1;
            } else if merging.quarantined.len() == quarantined {
                replayed.applied.push(kept);
            }
        }
        // Held again, each rewrote its row: not news.
        merging.held.clear();
        replayed.quarantined = std::mem::take(&mut merging.quarantined);
        self.store.write_changes(changes)?;
        Ok(replayed)
    }

    /// Room on the disk past the reserve, or [`Error::Full`].
    pub(crate) fn room(&self) -> Result<(), Error> {
        let free = self.config.disk.free(&self.dir)?;
        if free < RESERVE_BYTES {
            return Err(Error::Full { free });
        }
        Ok(())
    }

    /// The local nodes of `instance`'s scope not yet pushed, each author's
    /// oldest first.
    pub fn outbox(&self, instance: InstanceId) -> Result<Vec<Outgoing<Blake2b256>>, Error> {
        let mut writing = self.writing();
        let scope = self.scope(&mut writing, instance)?;
        scope.outbox().map_err(Error::Scope)
    }

    /// Mark local nodes of `instance`'s scope pushed: each `(author, seq)`
    /// and its author's earlier nodes.
    pub fn pushed(&self, instance: InstanceId, nodes: &[(Author, u64)]) -> Result<(), Error> {
        let mut writing = self.writing();
        let scope = self.scope(&mut writing, instance)?;
        Ok(scope.pushed(nodes)?)
    }

    /// The position of the agent's feed `instance`'s scope was read to:
    /// none before its first page.
    pub fn cursor(&self, instance: InstanceId) -> Result<Option<u64>, Error> {
        let mut writing = self.writing();
        Ok(self.scope(&mut writing, instance)?.cursor())
    }

    /// `instance`'s push queue: its local nodes sealed and not yet taken,
    /// by sequence number.
    pub fn queued(&self, instance: InstanceId) -> Result<Vec<(u64, Queued)>, Error> {
        self.store
            .queued(instance)?
            .into_iter()
            .map(|(seq, value)| Ok((seq, Queued::decode_exact(&value).ok_or(CorruptRow)?)))
            .collect()
    }

    /// Queue each `(seq, queued)` for `instance`'s local node `seq`, in one
    /// synced batch: written before they are sent, so a retry after a crash
    /// sends the same bytes.
    pub fn enqueue(&self, instance: InstanceId, queued: &[(u64, Queued)]) -> Result<(), Error> {
        let _writing = self.writing();
        let rows = queued
            .iter()
            .map(|(seq, queued)| (*seq, Some(queued.encode())));
        Ok(self.store.write_queue(instance, rows)?)
    }

    /// The agent took `instance`'s local nodes `seqs`: they and their
    /// author's earlier nodes are pushed, and their queued envelopes
    /// deleted, in one batch. A node no longer in the outbox only leaves
    /// the queue.
    pub fn sent(&self, instance: InstanceId, seqs: &[u64]) -> Result<(), Error> {
        let Some(last) = seqs.iter().max().copied() else {
            return Ok(());
        };
        let mut writing = self.writing();
        let author = self.author();
        let scope = self.scope(&mut writing, instance)?;
        let outgoing = scope
            .outbox()
            .map_err(Error::Scope)?
            .iter()
            .any(|node| node.author == author && node.seq <= last);
        if !outgoing {
            return Ok(self
                .store
                .write_queue(instance, seqs.iter().map(|seq| (*seq, None)))?);
        }
        for seq in seqs {
            let (meta, key) = self.store.queue_key(instance, *seq);
            scope.store_mut().stage(meta, &key, None);
        }
        let pushed = scope.pushed(&[(author, last)]);
        scope.store_mut().unstage();
        Ok(pushed?)
    }

    /// Each author's highest sequence number applied in `instance`'s
    /// scope: what the light node tells a peer it has.
    pub fn have(&self, instance: InstanceId) -> Result<BTreeMap<Author, u64>, Error> {
        let mut writing = self.writing();
        Ok(self.scope(&mut writing, instance)?.have())
    }

    /// The nodes of `instance`'s scope held for missing parents, and the
    /// parents to ask a peer for.
    pub fn wanted(&self, instance: InstanceId) -> Result<(usize, Vec<sync::Cid>), Error> {
        let mut writing = self.writing();
        let scope = self.scope(&mut writing, instance)?;
        Ok((scope.held(), scope.wanted()))
    }

    /// Cut `author` off in `instance`'s scope from sequence number `from`:
    /// its operations there and later already applied are filtered when
    /// the merge fields are read, never unapplied, and those that arrive
    /// later are quarantined. A cutoff already lower stands. The device
    /// set's removals give it, one past a removed device's node at its
    /// frontier, as the sealed read sets it
    /// ([`crate::personal::SealedSync::catch_up`]); an equivocation's is
    /// the scope's own. Exempt from the disk's reserve: it keeps data out.
    pub fn cut_off(&self, instance: InstanceId, author: Author, from: u64) -> Result<(), Error> {
        let _writing = self.writing();
        let snapshot = self.store.snapshot();
        let mut rows = Vec::new();
        for key in [
            keys::cutoff(instance, &author.0),
            keys::removed(instance, &author.0),
        ] {
            let stored_cutoff = match snapshot.get(&key)? {
                Some(bytes) => Some(
                    unstored(&bytes)
                        .and_then(Cutoff::decode_exact)
                        .ok_or(CorruptRow)?,
                ),
                None => None,
            };
            if stored_cutoff.is_none_or(|cutoff| from < cutoff.0) {
                rows.push((key, stored(&Cutoff(from).encode())));
            }
        }
        if rows.is_empty() {
            return Ok(());
        }
        Ok(self.store.write_rows(rows)?)
    }

    /// Query `instance`'s `method` with `arguments`, as `caller`, on the
    /// state as it stands: the agent program's query entry, which writes
    /// nothing.
    pub fn query(
        &self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> Result<Outcome, Error> {
        let snapshot = Arc::new(self.store.snapshot());
        let (time, seed) = snapshot.last()?.unwrap_or((0, [0; 32]));
        let work = Work::Query(Query {
            time,
            seed,
            caller,
            instance,
            method,
            arguments,
        });
        let output = self.refine(&self.machines, snapshot, &work)?;
        Ok(decode::<Outcome>(&output)?)
    }

    /// The id of `instance`'s scope: from its name and the key archive's
    /// naming secret, which is this store's for good from the first.
    pub fn scope_id(&self, instance: InstanceId) -> Result<merkle_crdt::Scope, Error> {
        Ok(merkle_crdt::Scope(
            self.store.scope_id(&sync::scope_name(instance))?,
        ))
    }

    /// One write operation at a time: each is refined on the state the one
    /// before it left. The lock holds the scopes.
    fn writing(&self) -> MutexGuard<'_, BTreeMap<InstanceId, Scope>> {
        self.writing.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `instance`'s scope, opened in the store at its first use; none for
    /// an instance not installed.
    fn scope<'w>(
        &self,
        scopes: &'w mut BTreeMap<InstanceId, Scope>,
        instance: InstanceId,
    ) -> Result<&'w mut Scope, Error> {
        match scopes.entry(instance) {
            std::collections::btree_map::Entry::Occupied(scope) => Ok(scope.into_mut()),
            std::collections::btree_map::Entry::Vacant(vacant) => {
                let installed = self.store.snapshot().get(&keys::installed(instance))?;
                if installed.is_none() {
                    return Err(Error::NotInstalled);
                }
                let name = format!("scope-{:08x}", instance.0);
                let store = FjallStore::with_rows(
                    self.store.database(),
                    &name,
                    self.store.rows_keyspace().clone(),
                )?;
                let id = self.scope_id(instance)?;
                let replica = Replica::open(ScopeStore::new(store), id).map_err(Error::Scope)?;
                Ok(vacant.insert(replica))
            }
        }
    }

    /// The next local operation's time and seed: its time the wall clock's,
    /// never before the last local operation's, and its seed the operating
    /// system's.
    fn next(&self, snapshot: &Snapshot) -> Result<(u64, [u8; 32]), Error> {
        let latest = snapshot.last()?.map_or(0, |(time, _)| time);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_millis() as u64);
        let mut seed = [0; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|error| Error::Fault(Fault::Infrastructure(format!("randomness: {error}"))))?;
        Ok((now.max(latest), seed))
    }

    /// An install's refine output applied over `snapshot` as a node's
    /// accumulate applies it: its one step's outcome, and the rows the
    /// operation writes.
    fn applied(&self, snapshot: &Snapshot, output: &[u8]) -> Result<(Outcome, Written), Error> {
        let (result, pages) = split_output(output).ok_or_else(unexpected)?;
        let outcome = match result.steps.as_slice() {
            [Step::Ran(run)] => run.outcome.clone(),
            [Step::Refused { .. }] => return Err(Error::Refused),
            _ => return Err(unexpected()),
        };
        let mut applying = Applying {
            snapshot,
            written: Default::default(),
        };
        let applied = catch_unwind(AssertUnwindSafe(|| {
            apply(&mut applying, &result, Host::Vos { pages: &pages })
        }))
        .map_err(|panic| Fault::Infrastructure(format!("panicked: {}", panic_message(&*panic))))?;
        if !applied {
            return Err(Error::NotApplied);
        }
        Ok((outcome, applying.written))
    }

    /// An operation of `instance`'s scope, `call` as `origin`, run on the
    /// merge entry over `state`: its one step.
    fn merge(
        &self,
        instance: InstanceId,
        origin: &Origin,
        call: &Call,
        state: Arc<dyn StateReader>,
    ) -> Result<Run, Error> {
        let work = Work::Merge(Merge {
            time: call.time,
            seed: call.seed,
            origin: *origin,
            instance,
            method: call.method,
            arguments: call.arguments.clone(),
        });
        let output = self.refine(&self.machines, state, &work)?;
        let (result, _) = split_output(&output).ok_or_else(unexpected)?;
        match result.steps.into_iter().next() {
            Some(Step::Ran(run)) => Ok(run),
            Some(Step::Refused { .. }) => Err(Error::Refused),
            _ => Err(unexpected()),
        }
    }

    /// Run the agent program's refine on `work` over `snapshot`; a panic in
    /// it, a store read's, is a fault.
    fn refine(
        &self,
        machines: &Machines,
        snapshot: Arc<dyn StateReader>,
        work: &Work,
    ) -> Result<Vec<u8>, Error> {
        let ran = catch_unwind(AssertUnwindSafe(|| {
            machines.refine(snapshot, LOCAL, work, defaults::REFINE_GAS)
        }))
        .map_err(|panic| Fault::Infrastructure(format!("panicked: {}", panic_message(&*panic))))?;
        Ok(ran?.0)
    }
}

fn unexpected() -> Error {
    Error::Fault(Fault::Agent("its output is not one step".into()))
}

/// The release of the actor installed at `instance`, if one is.
fn release(snapshot: &Snapshot, instance: InstanceId) -> Result<Option<u32>, Error> {
    match snapshot.get(&keys::release(instance))? {
        Some(bytes) => Ok(Some(
            unstored(&bytes)
                .and_then(u32::decode_exact)
                .ok_or(CorruptRow)?,
        )),
        None => Ok(None),
    }
}

/// What ingesting nodes did: the nodes' report, and the operations they
/// carried that were held or quarantined.
#[derive(Debug, Default)]
pub struct Ingest {
    pub nodes: Ingested<Blake2b256>,
    pub held: Vec<Held>,
    pub quarantined: Vec<Quarantined>,
}

/// What a replay did: the held operations it applied, those it
/// quarantined, and the number still held.
#[derive(Debug, Default)]
pub struct Replayed {
    pub applied: Vec<Held>,
    pub quarantined: Vec<Quarantined>,
    pub held: usize,
}

/// The store as of a snapshot under a batch's writes, which its reads
/// see: a replay's rows.
struct Staged<'a> {
    snapshot: &'a Snapshot,
    written: &'a mut Written,
}

impl Rows for Staged<'_> {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        match self.written.get(key) {
            Some(value) => value.clone(),
            None => self.snapshot.get(key).expect("a store read"),
        }
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
        self.written.insert(key.to_vec(), value.map(<[u8]>::to_vec));
    }
}

/// The store's state version: the installs applied.
fn version(snapshot: &Snapshot) -> Result<u64, Error> {
    match snapshot.get(&keys::version())? {
        Some(bytes) => unstored(&bytes)
            .and_then(|bytes| u64::decode(bytes).ok())
            .map(|(version, _)| version)
            .ok_or_else(|| {
                Error::Fault(Fault::Invariant("the state version does not read".into()))
            }),
        None => Ok(0),
    }
}

/// `op`, as `origin` of the node `cid`, kept for `why`.
fn keep<W>(cid: &sync::Cid, origin: &Origin, op: &Op, why: W) -> Kept<W> {
    Kept {
        cid: cid.clone(),
        origin: *origin,
        op: op.clone(),
        why,
    }
}

/// A scope's nodes applied through the merge entry: each operation run
/// over the store as the batch began and the batch's writes since, its
/// rows written through the scope's.
struct Merging<'a> {
    light: &'a Light,
    instance: InstanceId,
    snapshot: Arc<Snapshot>,
    /// The batch's writes so far, which later runs read above the store.
    written: Arc<Written>,
    /// The release of the instance's actor installed here.
    release: u32,
    /// A local operation: its handler's failure declines it.
    local: bool,
    /// A local operation's outcome.
    outcome: Option<Outcome>,
    /// The peers' operations held, and quarantined.
    held: Vec<Held>,
    quarantined: Vec<Quarantined>,
}

impl<'a> Merging<'a> {
    fn new(
        light: &'a Light,
        instance: InstanceId,
        snapshot: Snapshot,
        local: bool,
    ) -> Result<Self, Error> {
        Ok(Self {
            light,
            instance,
            release: release(&snapshot, instance)?.unwrap_or(0),
            snapshot: Arc::new(snapshot),
            written: Arc::new(BTreeMap::new()),
            local,
            outcome: None,
            held: Vec::new(),
            quarantined: Vec::new(),
        })
    }

    fn hold(&mut self, kept: Held, rows: &mut dyn Rows) {
        sync::hold(self.instance, &kept, rows);
        self.held.push(kept);
    }

    fn quarantine(&mut self, kept: Quarantined, rows: &mut dyn Rows) {
        sync::quarantine(self.instance, &kept, rows);
        self.quarantined.push(kept);
    }

    /// Run `op` as `origin`, of the node `cid`, its writes through `rows`.
    /// A local operation runs, or declines with nothing recorded. A
    /// peer's is checked first: one whose author was removed at its number,
    /// or whose frame no device records, is quarantined; one of a kind this
    /// build does not know, or of a later release than the one installed,
    /// is held. It then runs: done, its rows are written; its run faulting
    /// here, it is held for a replay; failing otherwise, which no issuing
    /// device records, it is quarantined. So no peer's node stops the
    /// scope's sync, and none writes what its author's device did not.
    fn run(
        &mut self,
        cid: &sync::Cid,
        origin: &Origin,
        op: &Op,
        rows: &mut dyn Rows,
    ) -> Result<(), Halt> {
        if !self.local {
            let cutoff = sync::removed(rows, self.instance, &origin.author)?;
            if cutoff.is_some_and(|cutoff| !cutoff.admits(origin.seq)) {
                self.quarantine(keep(cid, origin, op, Quarantine::CutOff), rows);
                return Ok(());
            }
        }
        let call = match op {
            Op::Call(call) => call,
            Op::Unknown { .. } => {
                self.hold(keep(cid, origin, op, Hold::Kind), rows);
                return Ok(());
            }
        };
        if !self.local {
            if call.arguments.len() > MAX_ARGUMENTS {
                self.quarantine(keep(cid, origin, op, Quarantine::Invalid), rows);
                return Ok(());
            }
            if call.release > self.release {
                self.hold(keep(cid, origin, op, Hold::Release), rows);
                return Ok(());
            }
        }
        let state = Arc::new(Layered {
            snapshot: Arc::clone(&self.snapshot),
            written: Arc::clone(&self.written),
        });
        let run = match self.light.merge(self.instance, origin, call, state) {
            Ok(run) => run,
            Err(error) if self.local => return Err(Halt::Error(error)),
            Err(_) => {
                self.hold(keep(cid, origin, op, Hold::Fault), rows);
                return Ok(());
            }
        };
        match run.outcome {
            Outcome::Done(_) => {
                let mut mirrored = Mirrored {
                    rows,
                    written: Arc::make_mut(&mut self.written),
                };
                for write in &run.writes {
                    let value = write.value.as_deref().map(stored);
                    mirrored.write(&write.key, value.as_deref());
                }
            }
            outcome if self.local => return Err(Halt::Declined(outcome)),
            // The device lacks a program its state names: its fault.
            Outcome::Failed {
                code: Failure::Unloadable | Failure::InRefine,
                ..
            } => self.hold(keep(cid, origin, op, Hold::Fault), rows),
            Outcome::Failed { code, .. } => {
                self.quarantine(keep(cid, origin, op, Quarantine::Failed(code)), rows)
            }
            Outcome::Started(_) => {
                self.quarantine(keep(cid, origin, op, Quarantine::Invalid), rows)
            }
        }
        if self.local {
            self.outcome = Some(run.outcome);
        }
        Ok(())
    }
}

impl Apply<Blake2b256, Ops> for Merging<'_> {
    type Error = Halt;

    fn apply(
        &mut self,
        event: Event<'_, Blake2b256, Ops>,
        rows: &mut dyn Rows,
    ) -> Result<(), Halt> {
        sync::apply_node(self.instance, &event, rows, |cid, origin, op, rows| {
            self.run(cid, origin, op, rows)
        })
    }
}

/// The store as a batch began, under the batch's writes since: what an
/// operation's run reads.
struct Layered {
    snapshot: Arc<Snapshot>,
    written: Arc<Written>,
}

impl StateReader for Layered {
    fn read(&self, key: &[u8], offset: usize, max: usize) -> Option<(usize, Vec<u8>)> {
        match self.written.get(key) {
            Some(value) => value
                .as_deref()
                .map(|value| value_window(value, offset, max)),
            None => self.snapshot.read(key, offset, max),
        }
    }

    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> Box<dyn Iterator<Item = (Vec<u8>, usize)> + 'a> {
        let start = match after {
            Some(after) if after >= prefix => Bound::Excluded(after),
            _ => Bound::Included(prefix),
        };
        let mut written = self
            .written
            .range::<[u8], _>((start, Bound::Unbounded))
            .take_while(move |(key, _)| key.starts_with(prefix))
            .peekable();
        let mut stored = self.snapshot.rows(prefix, after).peekable();
        Box::new(std::iter::from_fn(move || {
            loop {
                let order = match (stored.peek(), written.peek()) {
                    (None, None) => return None,
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (Some((key, _)), Some((over, _))) => key.as_slice().cmp(over.as_slice()),
                };
                match order {
                    Ordering::Less => return stored.next(),
                    Ordering::Equal => {
                        stored.next();
                    }
                    Ordering::Greater => {}
                }
                let (key, value) = written.next().expect("peeked");
                if let Some(value) = value {
                    return Some((key.clone(), value.len()));
                }
            }
        }))
    }
}

/// The store's programs, and those an install brings, which its run reads
/// before they are stored with its rows.
struct Installing {
    store: Store,
    programs: BTreeMap<[u8; 32], Vec<u8>>,
}

impl ProgramStore for Installing {
    fn get(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        match self.programs.get(hash) {
            Some(program) => Some(program.clone()),
            None => self.store.get(hash),
        }
    }

    fn pinned_by(&self, hash: &[u8; 32], agent: AgentId) -> bool {
        self.store.pinned_by(hash, agent)
    }
}
