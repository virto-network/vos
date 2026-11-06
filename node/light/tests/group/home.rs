//! A home: `Personal` installed in the default agent on a host that runs a
//! node's refine and applies its work results as a node's accumulate does,
//! one batch a call; and ingress's part, each call's signature checked
//! against its key before the call runs. The batch time is the test's.

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;
use std::sync::{Arc, Mutex, PoisonError};

use ed25519_dalek::{Signer, SigningKey, Verifier};
use vos_exec::{Machines, ProgramStore, StateReader};
use vos_light::release::{self, Package};
use vos_pvm::PvmBackend;
use vos_pvm::pool::{MachinePool, OuterMachines};
use vos_testkit::programs;
use vos_wire::abi::Failure;
use vos_wire::abi::cap::Target;
use vos_wire::apply::{Host, State, apply};
use vos_wire::batch::{Admin, Batch, Input, Query, Request, Work};
use vos_wire::defaults::SESSION_EXPIRY_MS;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session};
use vos_wire::ingress::{Grant, call_message};
use vos_wire::personal::{Entry, PersonalError, Policy};
use vos_wire::records::unstored;
use vos_wire::result::{Outcome, Step, split_output};
use vos_wire::{Decode, Encode, SpaceId, WindowClock, keys};

pub const PERSONAL: InstanceId = InstanceId(5);
/// The agent's identity, which calls are signed for.
pub const IDENTITY: [u8; 32] = [0x1d; 32];
const AGENT: AgentId = AgentId(7);
const GAS: u64 = 4_000_000_000;
/// The batch time a test's home starts at.
pub const T0: u64 = 1_800_000_000_000;

/// The home's rows.
#[derive(Clone, Default)]
struct Rows(Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>);

impl StateReader for Rows {
    fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.lock().unwrap().get(key).cloned()
    }

    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a> {
        let start = match after {
            Some(after) if after >= prefix => Bound::Excluded(after.to_vec()),
            _ => Bound::Included(prefix.to_vec()),
        };
        let rows: Vec<(Vec<u8>, Vec<u8>)> = self
            .0
            .lock()
            .unwrap()
            .range((start, Bound::Unbounded))
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        Box::new(rows.into_iter())
    }
}

impl State for Rows {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        StateReader::read(self, key)
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
        let mut rows = self.0.lock().unwrap();
        match value {
            Some(value) => rows.insert(key.to_vec(), value.to_vec()),
            None => rows.remove(key),
        };
    }
}

/// The programs installed, each pinned.
#[derive(Default)]
struct Programs(Mutex<HashMap<[u8; 32], Vec<u8>>>);

impl ProgramStore for Programs {
    fn get(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(hash)
            .cloned()
    }

    fn pinned_by(&self, hash: &[u8; 32], _: AgentId) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(hash)
    }
}

/// A call's reply: its batch time, and its outcome.
pub struct Reply {
    pub at: u64,
    pub outcome: Outcome,
    /// The call's signed message and signature, as ingress verified them.
    pub message: Vec<u8>,
    pub signature: [u8; 64],
}

impl Reply {
    /// The handler's answer: its reply, or `Personal`'s error.
    pub fn answer<T: Decode>(&self) -> Result<T, PersonalError> {
        match &self.outcome {
            Outcome::Done(bytes) => Ok(T::decode_exact(bytes).expect("the reply decodes")),
            Outcome::Failed {
                code: Failure::Handler,
                detail,
            } => Err(PersonalError::decode_exact(detail).expect("the error decodes")),
            other => panic!("{other:?}"),
        }
    }
}

pub struct Home {
    machines: Machines,
    rows: Rows,
    personal: Vec<u8>,
    sessions: BTreeMap<[u8; 32], (Session, u64, u64)>,
    pub now: u64,
}

/// The release artifacts: the default agent, linked, and `Personal`'s
/// package.
pub fn artifacts() -> &'static (Vec<u8>, Package) {
    static ARTIFACTS: std::sync::OnceLock<(Vec<u8>, Package)> = std::sync::OnceLock::new();
    ARTIFACTS.get_or_init(|| {
        let read = |path: std::path::PathBuf| std::fs::read(path).unwrap();
        let agent = release::agent(&read(programs::agent_elf())).unwrap();
        let personal = release::package(&read(programs::personal_elf())).unwrap();
        (agent, personal)
    })
}

impl Home {
    /// `Personal` installed, its role `homes` granted to `homes`.
    pub fn new(homes: &SigningKey, policy: Policy) -> Self {
        let (agent, package) = artifacts();
        let backend = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            PvmBackend::ForceRecompiler
        } else {
            PvmBackend::ForceInterpreter
        };
        let program = OuterMachines::with_idle_limit(agent, backend, 1).unwrap();
        let pool = Arc::new(MachinePool::with_idle_limits(8, 2));
        let store = Arc::new(Programs::default());
        for (hash, program) in package.checked().unwrap() {
            pool.install(program).unwrap();
            store.0.lock().unwrap().insert(hash, program.to_vec());
        }
        let mut home = Self {
            machines: Machines {
                program: Arc::new(program),
                pool,
                programs: store,
            },
            rows: Rows::default(),
            personal: package.programs[0].clone(),
            sessions: BTreeMap::new(),
            now: T0,
        };
        let homes_key = homes.verifying_key().to_bytes();
        home.batch(vec![
            Input::Admin(Admin::Install {
                instance: PERSONAL,
                derivation: package.derivation.clone(),
                roles: vec![(b"homes".to_vec(), 1)],
                target: Target::Vos,
                space: SpaceId::NONE,
                clock: WindowClock::DEFAULT,
            }),
            Input::Admin(Admin::SetRole(Grant {
                principal: Principal::Client(homes_key),
                role: Some(1),
            })),
        ]);
        home.call(homes, "configure", policy.encode())
            .answer::<vos_wire::personal::Recorded>()
            .unwrap();
        home
    }

    pub fn method(&self, name: &str) -> MethodId {
        programs::method(&self.personal, name)
    }

    /// The agent as a device group names it.
    pub fn agent(&self) -> vos_light::group::Agent {
        vos_light::group::Agent {
            identity: IDENTITY,
            instance: PERSONAL,
            commit: self.method("commit"),
            remove: self.method("remove"),
        }
    }

    fn version(&self) -> u64 {
        match StateReader::read(&self.rows, &keys::version()) {
            Some(bytes) => unstored(&bytes)
                .and_then(|bytes| u64::decode(bytes).ok())
                .map(|(version, _)| version)
                .unwrap(),
            None => 0,
        }
    }

    /// `inputs` refined and applied at the batch time, which moves a
    /// millisecond on: each step.
    fn batch(&mut self, inputs: Vec<Input>) -> Vec<Step> {
        let work = Work::Batch(Batch {
            version: self.version(),
            time: self.now,
            seed: [0; 32],
            budget: GAS,
            inputs,
        });
        let state = Arc::new(self.rows.clone());
        let (output, _) = self.machines.refine(state, AGENT, &work, GAS).unwrap();
        let (result, pages) = split_output(&output).unwrap();
        assert!(apply(&mut self.rows, &result, Host::Vos { pages: &pages }));
        self.now += 1;
        result.steps
    }

    /// A call of `name` with `arguments` signed by `key`, verified as
    /// ingress verifies it, then run alone in a batch.
    pub fn call(&mut self, key: &SigningKey, name: &str, arguments: Vec<u8>) -> Reply {
        let public = key.verifying_key().to_bytes();
        let (session, sequence) = self.session(public);
        let method = self.method(name);
        let message = call_message(&IDENTITY, &session, sequence, PERSONAL, method, &arguments);
        let signature = key.sign(&message);
        key.verifying_key()
            .verify(&message, &signature)
            .expect("ingress verifies the call");
        let at = self.now;
        let steps = self.batch(vec![Input::Request(Request {
            session,
            sequence,
            caller: Principal::Client(public),
            instance: PERSONAL,
            method,
            arguments,
        })]);
        let outcome = match steps.into_iter().next() {
            Some(Step::Ran(run)) => run.outcome,
            other => panic!("{name}: {other:?}"),
        };
        Reply {
            at,
            outcome,
            message,
            signature: signature.to_bytes(),
        }
    }

    /// `key`'s session for a call now, and the call's sequence.
    fn session(&mut self, key: [u8; 32]) -> (Session, u64) {
        let now = self.now;
        let fresh = || {
            let mut name = [0; 16];
            name[..8].copy_from_slice(&now.to_le_bytes());
            (Session { key, name, t0: now }, 0, now)
        };
        let entry = self.sessions.entry(key).or_insert_with(fresh);
        if entry.2 + SESSION_EXPIRY_MS / 2 < now {
            *entry = fresh();
        }
        entry.1 += 1;
        entry.2 = now;
        (entry.0, entry.1)
    }

    /// `key`'s query of `name` at the batch time.
    pub fn query<T: Decode>(
        &self,
        key: [u8; 32],
        name: &str,
        arguments: Vec<u8>,
    ) -> Result<T, PersonalError> {
        let work = Work::Query(Query {
            time: self.now,
            seed: [0; 32],
            caller: Principal::Client(key),
            instance: PERSONAL,
            method: self.method(name),
            arguments,
        });
        let (output, _) = self
            .machines
            .refine(Arc::new(self.rows.clone()), AGENT, &work, GAS)
            .unwrap();
        let outcome = vos_exec::decode::<Outcome>(&output).unwrap();
        Reply {
            at: self.now,
            outcome,
            message: Vec::new(),
            signature: [0; 64],
        }
        .answer()
    }

    /// The control log from `from` to its head, read as `key`.
    pub fn log(&self, key: [u8; 32], from: u64) -> Result<Vec<(u64, Entry)>, PersonalError> {
        let mut entries = Vec::new();
        let mut next = from;
        loop {
            let page: Vec<(u64, Entry)> = self.query(key, "log", next.encode())?;
            let Some((last, _)) = page.last() else {
                return Ok(entries);
            };
            next = last + 1;
            entries.extend(page);
        }
    }

    pub fn pass(&mut self, ms: u64) {
        self.now += ms;
    }
}
