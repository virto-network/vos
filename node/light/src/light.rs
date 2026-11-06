//! The light node (`light-node.md` §2.1): one local agent, the default
//! agent's program, run on the interpreter over the light node's own store,
//! with no log. Each operation runs one entry of the agent program and is
//! committed in one batch: an install (a batch of one install, as a node's
//! install), a call (the merge entry, `Work::Merge`), and, writing nothing,
//! a query. No Raft, no leader, no peers, no sessions, no sweeps; and no
//! accumulate run: the light node applies an entry's work result itself,
//! by the code a node's accumulate runs (`vos_wire::apply`).

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use vos_exec::{Fault, Machines, ProgramStore, StateReader, decode, panic_message};
use vos_pvm::PvmBackend;
use vos_pvm::pool::{MachinePool, OuterMachines};
use vos_wire::abi::cap::Target;
use vos_wire::apply::{Host, apply};
use vos_wire::batch::{Admin, Batch, Input, Merge, Query, Work};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_wire::records::unstored;
use vos_wire::result::{Outcome, Step, split_output};
use vos_wire::{Decode, SpaceId, WindowClock, defaults, keys};

use crate::release::Package;
use crate::store::{Applying, CACHE_BYTES, Operation, Snapshot, Store, StoreError};

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

/// Why an operation produced nothing.
#[derive(Debug)]
pub enum Error {
    /// The store failed: nothing of the operation was written.
    Store(StoreError),
    /// The agent program failed, or the run did: nothing was written.
    Fault(Fault),
    /// The agent program refused the operation, before running it.
    Refused,
    /// A package whose programs are not its derivation's.
    Package,
    /// A package another transpiler's version derived: its programs are
    /// not the ones this light node's release names.
    Transpiler(u32),
    /// The agent program's work result does not apply to the state it was
    /// refined on: the agent program's fault.
    NotApplied,
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

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Store(error) => error.fmt(f),
            Error::Fault(fault) => f.write_str(fault.message()),
            Error::Refused => f.write_str("the agent refused the operation"),
            Error::Package => f.write_str("the package's programs are not its derivation's"),
            Error::Transpiler(version) => write!(
                f,
                "the package is transpiler {version}'s, not {}'s",
                crate::release::TRANSPILER
            ),
            Error::NotApplied => f.write_str("the operation's result does not apply"),
        }
    }
}

impl std::error::Error for Error {}

/// The light node: its store, the agent program's machines, and one lock
/// that runs its write operations one at a time.
pub struct Light {
    store: Store,
    machines: Machines,
    config: Config,
    writing: Mutex<()>,
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
        Ok(Self {
            store,
            machines,
            config,
            writing: Mutex::new(()),
        })
    }

    /// The light node's store.
    pub fn store(&self) -> &Store {
        &self.store
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
        let _writing = self.writing();
        let snapshot = self.store.snapshot();
        let (version, time, seed) = self.next(&snapshot)?;
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
        let (outcome, mut operation) = self.run(&machines, snapshot, &work)?;
        if let Outcome::Done(_) = outcome {
            operation.programs = programs
                .into_iter()
                .map(|(hash, program)| (hash, program.to_vec()))
                .collect();
        }
        self.store.commit(operation)?;
        Ok(outcome)
    }

    /// Call `instance`'s `method` with `arguments`, as `caller`: the
    /// agent program's merge entry, its writes committed in one batch. The
    /// handler's outcome.
    pub fn call(
        &self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> Result<Outcome, Error> {
        let _writing = self.writing();
        let snapshot = self.store.snapshot();
        let (version, time, seed) = self.next(&snapshot)?;
        let work = Work::Merge(Merge {
            version,
            time,
            seed,
            caller,
            instance,
            method,
            arguments,
        });
        let (outcome, operation) = self.run(&self.machines, snapshot, &work)?;
        self.store.commit(operation)?;
        Ok(outcome)
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

    /// One write operation at a time: each is refined on the state the one
    /// before it left.
    fn writing(&self) -> MutexGuard<'_, ()> {
        self.writing.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The next operation's state version, time and seed: its time the
    /// wall clock's, never before the last operation's, and its seed the
    /// operating system's.
    fn next(&self, snapshot: &Snapshot) -> Result<(u64, u64, [u8; 32]), Error> {
        let version = match snapshot.get(&keys::version())? {
            Some(bytes) => unstored(&bytes)
                .and_then(|bytes| u64::decode(bytes).ok())
                .map(|(version, _)| version)
                .ok_or_else(|| {
                    Error::Fault(Fault::Invariant("the state version does not read".into()))
                })?,
            None => 0,
        };
        let latest = snapshot.last()?.map_or(0, |(time, _)| time);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_millis() as u64);
        let mut seed = [0; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|error| Error::Fault(Fault::Infrastructure(format!("randomness: {error}"))))?;
        Ok((version, now.max(latest), seed))
    }

    /// Run `work`'s refine, a batch or a merge, on `machines` over
    /// `snapshot`, and apply its
    /// one step's work result there: the step's outcome, and what the
    /// operation writes.
    fn run(
        &self,
        machines: &Machines,
        snapshot: Snapshot,
        work: &Work,
    ) -> Result<(Outcome, Operation), Error> {
        let snapshot = Arc::new(snapshot);
        let output = self.refine(machines, Arc::clone(&snapshot), work)?;
        let unexpected = || Error::Fault(Fault::Agent("its output is not one step".into()));
        let (result, pages) = split_output(&output).ok_or_else(unexpected)?;
        let outcome = match result.steps.as_slice() {
            [Step::Ran(run)] => run.outcome.clone(),
            [Step::Refused { .. }] => return Err(Error::Refused),
            _ => return Err(unexpected()),
        };
        let mut applying = Applying {
            snapshot: &snapshot,
            written: Default::default(),
        };
        let applied = catch_unwind(AssertUnwindSafe(|| {
            apply(&mut applying, &result, Host::Vos { pages: &pages })
        }))
        .map_err(|panic| Fault::Infrastructure(format!("panicked: {}", panic_message(&*panic))))?;
        if !applied {
            return Err(Error::NotApplied);
        }
        let operation = Operation {
            rows: applying.written,
            programs: Vec::new(),
            time: result.time,
            seed: result.seed,
        };
        Ok((outcome, operation))
    }

    /// Run the agent program's refine on `work` over `snapshot`; a panic in
    /// it, a store read's, is a fault.
    fn refine(
        &self,
        machines: &Machines,
        snapshot: Arc<Snapshot>,
        work: &Work,
    ) -> Result<Vec<u8>, Error> {
        let state: Arc<dyn StateReader> = snapshot;
        let ran = catch_unwind(AssertUnwindSafe(|| {
            machines.refine(state, LOCAL, work, self.config.refine_gas)
        }))
        .map_err(|panic| Fault::Infrastructure(format!("panicked: {}", panic_message(&*panic))))?;
        Ok(ran?.0)
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
