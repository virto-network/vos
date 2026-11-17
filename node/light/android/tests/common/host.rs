// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A personal agent in process: `Personal` installed in the default agent
//! on a host that runs a node's refine and applies its work results as a
//! node's accumulate does, one batch a call, at the world's clock; and
//! ingress's part, each call's and query's signature checked before it
//! runs.

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;
use std::sync::{Arc, Mutex, PoisonError};

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use vos_abi::abi::cap::Target;
use vos_abi::ids::{AgentId, InstanceId, MethodId, Principal, Session};
use vos_abi::records::unstored;
use vos_abi::result::{Outcome, Step, split_output};
use vos_abi::{Decode, Encode, SpaceId, WindowClock, keys};
use vos_exec::{Machines, ProgramStore, StateReader};
use vos_light::release::Package;
use vos_pvm::PvmBackend;
use vos_pvm::pool::{MachinePool, OuterMachines};
use vos_wire::apply::{Host as Applied, State, apply};
use vos_wire::batch::{Admin, Batch, Input, Query, Request, Work};
use vos_wire::ingress::{self, Grant, QueryCall};
use vos_wire::personal::Policy;

pub const PERSONAL: InstanceId = InstanceId(5);
const GAS: u64 = 4_000_000_000;

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

/// The default agent's program, linked, and `Personal`'s package: the
/// facility's own artifact, and the package of this tree's personal agent
/// (`just build-programs`), as a release makes it.
fn artifacts() -> &'static (Vec<u8>, Package) {
    static ARTIFACTS: std::sync::OnceLock<(Vec<u8>, Package)> = std::sync::OnceLock::new();
    ARTIFACTS.get_or_init(|| {
        let agent = include_bytes!("../../release/agent.program").to_vec();
        let elf = std::fs::read(vos_testkit::programs::program_elf("vos-personal")).unwrap();
        let personal = vos_light::release::package(&elf, 1).unwrap();
        (agent, personal)
    })
}

/// One personal agent.
pub struct Host {
    machines: Machines,
    rows: Rows,
    agent: AgentId,
    pub identity: [u8; 32],
    /// The batch time of the last batch: each moves on at least a
    /// millisecond.
    last: u64,
}

impl Host {
    /// `Personal` installed at `agent`, whose identity is `identity`, its
    /// role `homes` granted to `homes`.
    pub fn new(agent: u32, identity: [u8; 32], homes: &SigningKey, now: u64) -> Self {
        let (program, package) = artifacts();
        let backend = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            PvmBackend::ForceRecompiler
        } else {
            PvmBackend::ForceInterpreter
        };
        let outer = OuterMachines::with_idle_limit(program, backend, 1).unwrap();
        let pool = Arc::new(MachinePool::with_idle_limits(8, 2));
        let store = Arc::new(Programs::default());
        for (hash, program) in package.checked().unwrap() {
            pool.install(program).unwrap();
            store.0.lock().unwrap().insert(hash, program.to_vec());
        }
        let mut host = Self {
            machines: Machines {
                program: Arc::new(outer),
                pool,
                programs: store,
            },
            rows: Rows::default(),
            agent: AgentId(agent),
            identity,
            last: 0,
        };
        let homes_key = homes.verifying_key().to_bytes();
        host.batch(
            now,
            vec![
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
            ],
        );
        host
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

    /// `inputs` refined and applied at `now` (or a millisecond past the
    /// last batch): each step, and the batch time.
    fn batch(&mut self, now: u64, inputs: Vec<Input>) -> (Vec<Step>, u64) {
        let time = now.max(self.last + 1);
        self.last = time;
        let work = Work::Batch(Batch {
            version: self.version(),
            time,
            seed: [0; 32],
            budget: GAS,
            inputs,
        });
        let state = Arc::new(self.rows.clone());
        let (output, _) = self.machines.refine(state, self.agent, &work, GAS).unwrap();
        let (result, pages) = split_output(&output).unwrap();
        assert!(apply(
            &mut self.rows,
            &result,
            Applied::Vos { pages: &pages }
        ));
        (result.steps, time)
    }

    fn ran(&mut self, now: u64, request: Request) -> (Outcome, u64) {
        let (steps, at) = self.batch(now, vec![Input::Request(request)]);
        match steps.into_iter().next() {
            Some(Step::Ran(run)) => (run.outcome, at),
            other => panic!("{other:?}"),
        }
    }

    /// A client's call as ingress takes it: its signature checked, then run
    /// alone in a batch at `now`.
    pub fn call(&mut self, now: u64, call: ingress::Call) -> (Outcome, u64) {
        let message = call.message(&self.identity);
        let key = ed25519_dalek::VerifyingKey::from_bytes(&call.session.key).unwrap();
        key.verify(
            &message,
            &ed25519_dalek::Signature::from_bytes(&call.signature),
        )
        .expect("ingress verifies the call");
        assert_eq!(call.instance, PERSONAL);
        self.ran(
            now,
            Request {
                session: call.session,
                sequence: call.sequence,
                caller: Principal::Client(call.session.key),
                instance: call.instance,
                method: call.method,
                arguments: call.arguments,
            },
        )
    }

    /// A query as ingress takes it: its signature checked, then run at
    /// `now`.
    pub fn query(&self, now: u64, query: &QueryCall) -> Outcome {
        let message = query.message(&self.identity);
        let key = ed25519_dalek::VerifyingKey::from_bytes(&query.key).unwrap();
        key.verify(
            &message,
            &ed25519_dalek::Signature::from_bytes(&query.signature),
        )
        .expect("ingress verifies the query");
        let work = Work::Query(Query {
            time: now.max(self.last),
            seed: [0; 32],
            caller: Principal::Client(query.key),
            instance: query.instance,
            method: query.method,
            arguments: query.arguments.clone(),
        });
        let (output, _) = self
            .machines
            .refine(Arc::new(self.rows.clone()), self.agent, &work, GAS)
            .unwrap();
        vos_exec::decode::<Outcome>(&output).unwrap()
    }

    /// `Homes`' call of `name` with `arguments`, under its key, at `now`.
    pub fn homes(
        &mut self,
        now: u64,
        homes: &SigningKey,
        name: &str,
        arguments: Vec<u8>,
    ) -> Outcome {
        let public = homes.verifying_key().to_bytes();
        let mut session_name = [0; 16];
        getrandom::getrandom(&mut session_name).unwrap();
        let session = Session {
            key: public,
            name: session_name,
            t0: now,
        };
        let method = MethodId(vos_light::method_id(name));
        let message =
            ingress::call_message(&self.identity, &session, 1, PERSONAL, method, &arguments);
        let call = ingress::Call {
            session,
            sequence: 1,
            instance: PERSONAL,
            method,
            arguments,
            signature: homes.sign(&message).to_bytes(),
        };
        self.call(now, call).0
    }

    /// The agent configured with `policy`, as `Homes` does at a claim.
    pub fn configure(&mut self, now: u64, homes: &SigningKey, policy: Policy) {
        let outcome = self.homes(now, homes, "configure", policy.encode());
        assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
    }
}
