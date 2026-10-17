//! The agent program's refine, accumulate and queries, run on executor
//! threads against a store snapshot. A store read that fails there panics,
//! which the executor turns into an infrastructure fault.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use vos_pvm::ExitReason;
use vos_pvm::accumulate_host::{self, ACCUMULATE_ENTRY, AccumulateContext, ServiceStorage};
use vos_pvm::pool::{CodeHash, MachinePool, OuterMachines};
use vos_pvm::refine::Machine;
use vos_pvm::refine_host::{ProgramSource, RefineContext, StateReader, serve_lookup};
use vos_wire::abi::surface::LOST;
use vos_wire::abi::{cap, code};
use vos_wire::batch::Work;
use vos_wire::ids::AgentId;
use vos_wire::jam::{AccumulateInput, Operand, RefineArgs};
use vos_wire::result::Write;
use vos_wire::{Decode, Encode, defaults};

use crate::blobs::Blobs;
use crate::fault::Fault;
use crate::lock;
use crate::store::Snapshot;

const REFINE_ENTRY: u32 = 0;

/// `historical_lookup`, which refine answers from the agent's programs.
const HISTORICAL_LOOKUP: u64 = vos_pvm::inner::gp_call::HISTORICAL_LOOKUP as u64;
/// The most of the agent's account of what it lost that a log line keeps.
const LOST_WHAT: usize = 256;

/// One agent's applied state, as refine reads it.
struct AgentState {
    snapshot: Arc<Snapshot>,
    agent: AgentId,
}

impl StateReader for AgentState {
    fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.snapshot.get(self.agent, key).expect("a store read")
    }

    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a> {
        Box::new(
            self.snapshot
                .scan(self.agent, prefix, after)
                .map(|row| row.expect("a store read")),
        )
    }
}

/// The programs `agent` may load, from the node's blob store: those it
/// pins, and those its batch installs, which the batch's apply pins. A JAM
/// service looks up only its own preimages: `historical_lookup` answers
/// these alone, and `instantiate` lends no other, though the node's pool
/// holds every agent's. A store that cannot be read faults the run, as
/// refine's other reads do.
struct AgentPrograms {
    blobs: Blobs,
    agent: AgentId,
    installing: BTreeSet<[u8; 32]>,
    /// Whether the agent pins a program, as this run asked.
    pinned: Mutex<HashMap<[u8; 32], bool>>,
}

impl AgentPrograms {
    fn new(blobs: &Blobs, agent: AgentId, work: &Work) -> Self {
        let installing = match work.batch() {
            Some(batch) => batch.installs().map(|program| program.0).collect(),
            None => BTreeSet::new(),
        };
        Self {
            blobs: blobs.clone(),
            agent,
            installing,
            pinned: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `hash` is one of the agent's programs.
    fn owns(&self, hash: &[u8; 32]) -> bool {
        if self.installing.contains(hash) {
            return true;
        }
        *lock(&self.pinned).entry(*hash).or_insert_with(|| {
            self.blobs
                .pinned_by(hash, self.agent.0)
                .expect("a pin read")
        })
    }

    /// The bytes of `hash`, if it is one of the agent's programs.
    fn get(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        if !self.owns(hash) {
            return None;
        }
        let program = self.blobs.get(hash).expect("a blob read");
        if program.is_none() {
            tracing::warn!(
                agent = self.agent.0,
                program = %crate::hex(&hash[..4]),
                "a program of the agent's is not stored"
            );
        }
        program
    }
}

impl ProgramSource for AgentPrograms {
    fn owns(&self, hash: &CodeHash) -> bool {
        AgentPrograms::owns(self, &hash.0)
    }

    fn program(&self, hash: &CodeHash) -> Option<Vec<u8>> {
        self.get(&hash.0)
    }
}

/// What runs the agent program: its machines, the pool of the programs
/// agents install, and the blob store those come from. Cheap to clone, for
/// an executor's job.
#[derive(Clone)]
pub(crate) struct Machines {
    pub(crate) program: Arc<OuterMachines>,
    pub(crate) pool: Arc<MachinePool>,
    pub(crate) blobs: Blobs,
}

impl Machines {
    /// Run the agent's refine on `work` for `agent` with `gas`, and a
    /// batch's decoding beyond it (`defaults::batch_start`): its output,
    /// if it halts, and the gas the run used.
    pub(crate) fn refine(
        &self,
        snapshot: Arc<Snapshot>,
        agent: AgentId,
        work: &Work,
        gas: u64,
    ) -> Result<(Vec<u8>, u64), Fault> {
        let Machines {
            program,
            pool,
            blobs,
        } = self;
        let arguments = RefineArgs::new(u64::from(agent.0), work.encode(), [0; 32]).encode();
        let gas = match work.batch() {
            Some(batch) => gas + defaults::batch_start(batch, arguments.len()),
            None => gas,
        };
        let programs = Arc::new(AgentPrograms::new(blobs, agent, work));
        let invocation = RefineContext::new(program.load(REFINE_ENTRY, &arguments, gas)?)
            .with_pool(Arc::clone(pool))
            .with_programs(Arc::clone(&programs) as Arc<dyn ProgramSource>)
            .with_state(Arc::new(AgentState { snapshot, agent }))
            .try_run_with_host(|id, machine| serve(id, machine, &programs))?;
        let used = invocation.gas_used;
        let output = if invocation.exit == ExitReason::HostCall(LOST) {
            let registers = invocation.registers;
            let mut what = vec![0; (registers[8] as usize).min(LOST_WHAT)];
            if !invocation
                .memory()
                .read_bytes_checked(registers[7] as u32, &mut what)
            {
                what.clear();
            }
            let what = String::from_utf8_lossy(&what);
            Err(Fault::Storage(format!(
                "agent {} lost state it wrote: {what}",
                agent.0
            )))
        } else if invocation.exit != ExitReason::Halt {
            Err(Fault::Agent(format!(
                "refine stopped: {:?}",
                invocation.exit
            )))
        } else {
            invocation
                .output_bounded(cap::OUTPUT)
                .ok_or_else(|| Fault::Agent("refine's output is out of bounds".into()))
        };
        program.restore(invocation);
        output.map(|output| (output, used))
    }

    /// Run the agent's accumulate on one work result: the writes to apply,
    /// one per key, if it halts.
    pub(crate) fn accumulate(
        &self,
        snapshot: Arc<Snapshot>,
        agent: AgentId,
        result: Vec<u8>,
        gas: u64,
    ) -> Result<Vec<Write>, Fault> {
        let input = AccumulateInput::Operand(Operand {
            gas_limit: gas,
            ..Operand::new(result)
        })
        .encode();
        let inputs = [input];
        let mut storage = Overlay {
            snapshot,
            agent,
            written: BTreeMap::new(),
        };
        let service = u64::from(agent.0);
        let arguments = accumulate_host::arguments(0, service, inputs.len());
        let machine = self.program.load(ACCUMULATE_ENTRY, &arguments, gas)?;
        let invocation =
            AccumulateContext::new(machine, service, &inputs, &mut storage).try_run()?;
        let exit = invocation.exit.clone();
        self.program.restore(invocation);
        if exit != ExitReason::Halt {
            return Err(Fault::Agent(format!("accumulate stopped: {exit:?}")));
        }
        Ok(storage
            .written
            .into_iter()
            .map(|(key, value)| Write { key, value })
            .collect())
    }
}

/// The calls refine leaves to the node: `historical_lookup` from the
/// agent's programs ([`serve_lookup`]), and the agent's report of lost
/// state, which stops the refine; every other answers `WHAT`.
fn serve(id: u64, machine: &mut Machine, programs: &AgentPrograms) -> Result<(), ExitReason> {
    match id {
        LOST => Err(ExitReason::HostCall(LOST)),
        HISTORICAL_LOOKUP => serve_lookup(machine, u64::from(programs.agent.0), |hash| {
            programs.get(hash)
        }),
        _ => {
            machine.registers_mut()[7] = code::WHAT;
            Ok(())
        }
    }
}

/// Accumulate's view of storage: the snapshot, under the writes it made,
/// which its later reads see.
struct Overlay {
    snapshot: Arc<Snapshot>,
    agent: AgentId,
    written: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl ServiceStorage for Overlay {
    fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
        match self.written.get(key) {
            Some(value) => value.clone(),
            None => self.snapshot.get(self.agent, key).expect("a store read"),
        }
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) -> Option<usize> {
        let previous = match self.written.get(key) {
            Some(value) => value.as_ref().map(Vec::len),
            None => self
                .snapshot
                .get(self.agent, key)
                .expect("a store read")
                .map(|value| value.len()),
        };
        self.written.insert(key.to_vec(), value.map(<[u8]>::to_vec));
        previous
    }
}

/// Decode the agent program's output as `T`.
pub(crate) fn decode<T: Decode>(bytes: &[u8]) -> Result<T, Fault> {
    T::decode(bytes)
        .map(|(value, _)| value)
        .map_err(|error| Fault::Agent(format!("undecodable output: {error:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blobs::Keep;
    use crate::store::{Fjall, PersistMode};
    use vos_pvm::accumulate_host::SELF_SERVICE;
    use vos_pvm_program::{CodeBlob, StandardProgram, build_standard_program};
    use vos_wire::abi::cap::Target;
    use vos_wire::batch::{Admin, Batch, Input, Query};
    use vos_wire::ids::{InstanceId, MethodId, Principal, ProgramHash};

    /// `historical_lookup` of `hash` in `service`'s preimages, served for
    /// `programs` into a machine whose arguments are the hash: the bytes it
    /// wrote, or `None` for `NONE`.
    fn lookup(programs: &AgentPrograms, service: u64, hash: &[u8; 32]) -> Option<Vec<u8>> {
        let blob = build_standard_program(&StandardProgram {
            ro_data: vec![],
            rw_data: vec![],
            heap_pages: 0,
            stack_size: 4096,
            code: CodeBlob {
                jump_table: vec![],
                code: vec![0],
                bitmask: vec![1],
            },
        })
        .unwrap();
        let mut machine = Machine::load(&blob, hash, 1_000_000).unwrap();
        let registers = machine.registers_mut();
        let out = registers[1] - 4096;
        registers[8] = registers[7];
        registers[7] = service;
        registers[9] = out;
        registers[10] = 0;
        registers[11] = 4096;
        serve(HISTORICAL_LOOKUP, &mut machine, programs).unwrap();
        let len = machine.registers()[7];
        if len == code::NONE {
            return None;
        }
        let mut bytes = vec![0; len as usize];
        assert!(machine.memory().read_bytes_checked(out as u32, &mut bytes));
        Some(bytes)
    }

    /// An agent's programs are those it pins and those its batch installs:
    /// `historical_lookup` reads no other, nor another service's, and the
    /// program source owns no other, so `instantiate` lends none from the
    /// pool, though another agent's is stored and pooled here.
    #[test]
    fn an_agent_reads_only_its_own_programs() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path().join("store")).unwrap();
        let blobs = Blobs::open(dir.path().join("blobs"), &store).unwrap();
        let stored = |bytes: Vec<u8>| {
            let program = Arc::new(bytes);
            let blob = crate::blobs::blob_ref(&program);
            smol::block_on(blobs.put(blob, Arc::clone(&program), Keep::Aged)).unwrap();
            (blob.hash, program.to_vec())
        };
        let (pinned, pinned_bytes) = stored(vec![1, 2, 3]);
        let (installed, installed_bytes) = stored(vec![4, 5]);
        let mut batch = store.batch();
        batch.pin(&pinned, AgentId(1));
        batch.commit(PersistMode::SyncAll).unwrap();

        let query = Work::Query(Query {
            time: 0,
            seed: [0; 32],
            caller: Principal::Client([1; 32]),
            instance: InstanceId(1),
            method: MethodId(1),
            arguments: Vec::new(),
        });
        let install = Work::Batch(Batch {
            version: 0,
            time: 0,
            seed: [0; 32],
            budget: 0,
            inputs: vec![Input::Admin(Admin::Install {
                instance: InstanceId(1),
                derivation: vos_wire::records::Derivation {
                    program: ProgramHash(installed),
                    kernels: Vec::new(),
                    elf: [0; 32],
                    transpiler: 0,
                    heap: 0,
                },
                roles: Vec::new(),
                target: Target::Vos,
            })],
        });
        let programs = |agent, work| AgentPrograms::new(&blobs, AgentId(agent), work);
        let (first, second) = (programs(1, &query), programs(2, &query));
        for service in [SELF_SERVICE, 1] {
            assert_eq!(lookup(&first, service, &pinned), Some(pinned_bytes.clone()));
        }
        assert_eq!(lookup(&first, 2, &pinned), None, "another service's");
        assert!(ProgramSource::owns(&first, &CodeHash(pinned)));
        assert_eq!(
            lookup(&second, SELF_SERVICE, &pinned),
            None,
            "another agent's"
        );
        assert!(!ProgramSource::owns(&second, &CodeHash(pinned)));
        assert_eq!(second.program(&CodeHash(pinned)), None);
        assert_eq!(
            lookup(&first, SELF_SERVICE, &installed),
            None,
            "one it never had"
        );
        assert_eq!(lookup(&first, SELF_SERVICE, &[9; 32]), None);

        let installing = programs(2, &install);
        assert_eq!(
            lookup(&installing, SELF_SERVICE, &installed),
            Some(installed_bytes)
        );
        assert!(ProgramSource::owns(&installing, &CodeHash(installed)));
        assert_eq!(lookup(&installing, SELF_SERVICE, &pinned), None);
        assert!(blobs.pinned_by_any(&pinned).unwrap());
        assert!(!blobs.pinned_by_any(&installed).unwrap());
    }
}
