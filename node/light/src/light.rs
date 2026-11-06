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

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::Bound;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use merkle_crdt::{
    Apply, Author, Event, FjallError, FjallStore, Ingested, Outgoing, Replica, Rows,
};
use vos_exec::{Fault, Machines, ProgramStore, StateReader, decode, panic_message};
use vos_pvm::PvmBackend;
use vos_pvm::pool::{MachinePool, OuterMachines};
use vos_wire::abi::Failure;
use vos_wire::abi::cap::Target;
use vos_wire::apply::{Host, apply};
use vos_wire::batch::{Admin, Batch, Input, Merge, Query, Work};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_wire::merge::{Cutoff, Origin};
use vos_wire::records::{stored, unstored};
use vos_wire::result::{Outcome, Run, Step, split_output};
use vos_wire::{Decode, Encode, SpaceId, WindowClock, defaults, keys};

use crate::release::Package;
use crate::store::{Applying, CACHE_BYTES, Operation, Snapshot, Store, StoreError};
use crate::sync::{self, Blake2b256, Call, CorruptRow, Mirrored, Op, Ops, ScopeStore};

/// The local agent, the light node's one: its id as the agent program
/// sees it.
pub const LOCAL: AgentId = AgentId(1);

/// How the light node runs.
#[derive(Clone, Debug)]
pub struct Config {
    /// Refine's gas for one run: a query's, a call's, or an install's
    /// budget.
    pub refine_gas: u64,
    /// The store's block cache.
    pub cache_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            refine_gas: defaults::REFINE_GAS,
            cache_bytes: CACHE_BYTES,
        }
    }
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
    /// A package whose programs are not its derivation's.
    Package,
    /// The agent program's work result does not apply to the state it was
    /// refined on: the agent program's fault.
    NotApplied,
    /// A scope of an instance not installed here: no handler could run its
    /// nodes.
    NotInstalled,
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
            Error::Package => f.write_str("the package's programs are not its derivation's"),
            Error::NotApplied => f.write_str("the operation's result does not apply"),
            Error::NotInstalled => f.write_str("the instance is not installed"),
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
        let store = Store::open(dir, config.cache_bytes)?;
        let unloadable = |error| Error::Fault(Fault::Agent(format!("{error:?}")));
        // One operation runs at a time: one machine kept idle.
        let program = OuterMachines::with_idle_limit(agent, PvmBackend::ForceInterpreter, 1)
            .map_err(unloadable)?;
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

    /// Install `package` as `instance`, its roles `roles`: its programs
    /// checked against its derivation and pooled, the install run as a
    /// node's, and its programs and rows committed in one batch. The
    /// install's outcome; a failed install stores nothing but the
    /// operation's mark.
    pub fn install(
        &self,
        instance: InstanceId,
        package: &Package,
        roles: Vec<(Vec<u8>, u8)>,
    ) -> Result<Outcome, Error> {
        let programs = package.checked().ok_or(Error::Package)?;
        for (_, program) in &programs {
            self.machines
                .pool
                .install(program)
                .map_err(|error| Error::Fault(Fault::Agent(format!("{error:?}"))))?;
        }
        let _writing = self.writing();
        let snapshot = self.store.snapshot();
        let version = version(&snapshot)?;
        let (time, seed) = self.next(&snapshot)?;
        let work = Work::Batch(Batch {
            version,
            time,
            seed,
            budget: self.config.refine_gas,
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
        if let Outcome::Done(_) = outcome {
            operation.programs = programs
                .into_iter()
                .map(|(hash, program)| (hash, program.to_vec()))
                .collect();
        }
        self.store.commit(operation)?;
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
        let mut writing = self.writing();
        let snapshot = self.store.snapshot();
        if snapshot.get(&keys::installed(instance))?.is_none() {
            return Ok(Outcome::failed(Failure::Unknown));
        }
        let (time, seed) = self.next(&snapshot)?;
        let ops = vec![Op::Call(Call {
            method,
            arguments,
            time,
            seed,
        })];
        let scope = self.scope(&mut writing, instance)?;
        let (meta, key, last) = self.store.last_row(time, &seed);
        scope.store_mut().stage(meta, key, last);
        let mut merging = Merging::new(self, instance, snapshot, true);
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
    /// with them. A handler's failure on an operation is its effect, the
    /// same on every device: nothing written; a method this build's
    /// program does not run is held in the scope's rows.
    pub fn ingest(
        &self,
        instance: InstanceId,
        nodes: impl IntoIterator<Item = Vec<u8>>,
        cursor: Option<u64>,
    ) -> Result<Ingested<Blake2b256>, Error> {
        let mut writing = self.writing();
        let scope = self.scope(&mut writing, instance)?;
        let snapshot = self.store.snapshot();
        let mut merging = Merging::new(self, instance, snapshot, false);
        match scope
            .ingest(nodes, cursor, &mut merging)
            .map_err(scope_error)
        {
            Ok(ingested) => Ok(ingested),
            Err(Halt::Declined(_)) => unreachable!("a peer's operation is never declined"),
            Err(Halt::Error(error)) => Err(error),
        }
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
    /// its operations there and later are filtered when the merge fields
    /// are read, never unapplied. A cutoff already lower stands. The
    /// device set's removals give it, past a removed device's frontier;
    /// an equivocation's is the scope's own.
    pub fn cut_off(&self, instance: InstanceId, author: Author, from: u64) -> Result<(), Error> {
        let _writing = self.writing();
        let key = keys::cutoff(instance, &author.0);
        let stored_cutoff = match self.store.snapshot().get(&key)? {
            Some(bytes) => Some(
                unstored(&bytes)
                    .and_then(Cutoff::decode_exact)
                    .ok_or(CorruptRow)?,
            ),
            None => None,
        };
        if stored_cutoff.is_some_and(|cutoff| cutoff.0 <= from) {
            return Ok(());
        }
        let row = stored(&Cutoff(from).encode());
        Ok(self.store.write_rows(vec![(key, row)])?)
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
            machines.refine(snapshot, LOCAL, work, self.config.refine_gas)
        }))
        .map_err(|panic| Fault::Infrastructure(format!("panicked: {}", panic_message(&*panic))))?;
        Ok(ran?.0)
    }
}

fn unexpected() -> Error {
    Error::Fault(Fault::Agent("its output is not one step".into()))
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

/// A scope's nodes applied through the merge entry: each operation run
/// over the store as the batch began and the batch's writes since, its
/// rows written through the scope's.
struct Merging<'a> {
    light: &'a Light,
    instance: InstanceId,
    snapshot: Arc<Snapshot>,
    /// The batch's writes so far, which later runs read above the store.
    written: Arc<Written>,
    /// A local operation: its handler's failure declines it.
    local: bool,
    /// A local operation's outcome.
    outcome: Option<Outcome>,
}

impl<'a> Merging<'a> {
    fn new(light: &'a Light, instance: InstanceId, snapshot: Snapshot, local: bool) -> Self {
        Self {
            light,
            instance,
            snapshot: Arc::new(snapshot),
            written: Arc::new(BTreeMap::new()),
            local,
            outcome: None,
        }
    }

    /// Run `call` as `origin`, of the node `cid`, its writes through
    /// `rows`. A peer's operation that its run fails, by its handler's
    /// failure or trap, writes nothing, as on every device; one this
    /// build's program does not run (`Unknown`), or whose run faults, is
    /// held for a build that runs it, so no peer's node stops the scope's
    /// sync.
    fn run(
        &mut self,
        cid: &sync::Cid,
        origin: &Origin,
        call: &Call,
        rows: &mut dyn Rows,
    ) -> Result<(), Halt> {
        let state = Arc::new(Layered {
            snapshot: Arc::clone(&self.snapshot),
            written: Arc::clone(&self.written),
        });
        let run = match self.light.merge(self.instance, origin, call, state) {
            Ok(run) => run,
            Err(error) if self.local => return Err(Halt::Error(error)),
            Err(_) => {
                sync::hold(self.instance, cid, origin, &Op::Call(call.clone()), rows);
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
            Outcome::Failed {
                code: Failure::Unknown,
                ..
            } => sync::hold(self.instance, cid, origin, &Op::Call(call.clone()), rows),
            _ => {}
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
        sync::apply_node(self.instance, &event, rows, |cid, origin, call, rows| {
            self.run(cid, origin, call, rows)
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
    fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
        match self.written.get(key) {
            Some(value) => value.clone(),
            None => self.snapshot.read(key),
        }
    }

    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a> {
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
                    return Some((key.clone(), value.clone()));
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
