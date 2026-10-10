//! The agent program's refine, accumulate and queries, run on executor
//! threads against a store snapshot. A store read that fails there panics,
//! which the executor turns into an infrastructure fault.

use std::collections::BTreeMap;
use std::sync::Arc;

use vos_pvm::ExitReason;
use vos_pvm::accumulate_host::{self, ACCUMULATE_ENTRY, AccumulateContext, ServiceStorage};
use vos_pvm::pool::{MachinePool, OuterMachines};
use vos_pvm::refine::Machine;
use vos_pvm::refine_host::{RefineContext, StateReader};
use vos_wire::abi::{cap, code};
use vos_wire::batch::Work;
use vos_wire::ids::{AgentId, ProgramHash};
use vos_wire::jam::{AccumulateInput, Operand, RefineArgs};
use vos_wire::result::Write;
use vos_wire::{Decode, Encode};

use crate::store::{Fjall, FjallSnapshot, Store, View};

/// The refine entry point.
const REFINE_ENTRY: u32 = 0;

/// `historical_lookup`, which refine answers from the stored programs.
const HISTORICAL_LOOKUP: u64 = 7;
const LOOKUP_GAS: u64 = 10;

/// Why a batch produced nothing.
#[derive(Debug)]
pub(crate) enum Fault {
    /// The agent program trapped, ran out of gas or answered nonsense:
    /// something in the batch may cause it.
    Agent(String),
    /// The node failed: a read, a backend or an executor. No input causes
    /// it, and it may pass.
    Infrastructure(String),
    /// A commit failed. fjall then refuses every later commit, so the node
    /// stops.
    Storage(String),
    /// The agent's state disagrees with its leader's: that agent stops.
    Invariant(String),
}

impl Fault {
    pub(crate) fn message(&self) -> &str {
        match self {
            Fault::Agent(message)
            | Fault::Infrastructure(message)
            | Fault::Storage(message)
            | Fault::Invariant(message) => message,
        }
    }
}

impl From<vos_pvm::refine::RefineError> for Fault {
    fn from(error: vos_pvm::refine::RefineError) -> Self {
        Fault::Infrastructure(format!("{error:?}"))
    }
}

/// One agent's applied state, as refine reads it.
struct AgentState {
    snapshot: Arc<FjallSnapshot>,
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

/// Run the agent's refine on `work` for `agent`: its output, if it halts.
pub(crate) fn refine(
    program: &OuterMachines,
    pool: &Arc<MachinePool>,
    store: &Fjall,
    snapshot: Arc<FjallSnapshot>,
    agent: AgentId,
    work: &Work,
    gas: u64,
) -> Result<Vec<u8>, Fault> {
    let arguments = RefineArgs {
        core: 0,
        item: 0,
        service: u64::from(agent.0),
        payload: work.encode(),
        package_hash: [0; 32],
    }
    .encode();
    let invocation = RefineContext::new(program.load(REFINE_ENTRY, &arguments, gas)?)
        .with_pool(Arc::clone(pool))
        .with_state(Arc::new(AgentState { snapshot, agent }))
        .try_run_with_host(|id, machine| serve(id, machine, store))?;
    let output = if invocation.exit != ExitReason::Halt {
        Err(Fault::Agent(format!(
            "refine stopped: {:?}",
            invocation.exit
        )))
    } else {
        invocation
            .output_bounded(cap::WORK_RESULT)
            .ok_or_else(|| Fault::Agent("refine's output is out of bounds".into()))
    };
    program.restore(invocation);
    output
}

/// The calls refine leaves to the node: `historical_lookup` from the
/// stored programs; every other answers `WHAT`.
fn serve(id: u64, machine: &mut Machine, store: &Fjall) -> Result<(), ExitReason> {
    if id != HISTORICAL_LOOKUP {
        machine.registers_mut()[7] = code::WHAT;
        return Ok(());
    }
    let registers = *machine.registers();
    let mut hash = [0u8; 32];
    if !machine
        .memory()
        .read_bytes_checked(registers[8] as u32, &mut hash)
    {
        return Err(ExitReason::Panic);
    }
    let blob = store.program(&ProgramHash(hash)).expect("a store read");
    let Some(blob) = blob else {
        machine.registers_mut()[7] = code::NONE;
        return Ok(());
    };
    let offset = (registers[10] as usize).min(blob.len());
    let len = (registers[11] as usize).min(blob.len() - offset);
    if !machine.charge(LOOKUP_GAS + len as u64) {
        return Err(ExitReason::OutOfGas);
    }
    if !machine
        .memory_mut()
        .write_bytes_checked(registers[9] as u32, &blob[offset..offset + len])
    {
        return Err(ExitReason::Panic);
    }
    machine.registers_mut()[7] = blob.len() as u64;
    Ok(())
}

/// Accumulate's view of storage: the snapshot, under the writes it made,
/// which its later reads see.
struct Overlay {
    snapshot: Arc<FjallSnapshot>,
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
        let previous = self.read(key).map(|value| value.len());
        self.written.insert(key.to_vec(), value.map(<[u8]>::to_vec));
        previous
    }
}

/// Run the agent's accumulate on one work result: the writes to apply,
/// one per key, if it halts.
pub(crate) fn accumulate(
    program: &OuterMachines,
    snapshot: Arc<FjallSnapshot>,
    agent: AgentId,
    result: Vec<u8>,
    gas: u64,
) -> Result<Vec<Write>, Fault> {
    let input = AccumulateInput::Operand(Operand {
        package_hash: [0; 32],
        segment_root: [0; 32],
        authorizer: [0; 32],
        payload_hash: [0; 32],
        gas_limit: gas,
        result: Ok(result),
        auth_trace: Vec::new(),
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
    let machine = program.load(ACCUMULATE_ENTRY, &arguments, gas)?;
    let invocation = AccumulateContext::new(machine, service, &inputs, &mut storage).try_run()?;
    let exit = invocation.exit.clone();
    program.restore(invocation);
    if exit != ExitReason::Halt {
        return Err(Fault::Agent(format!("accumulate stopped: {exit:?}")));
    }
    Ok(storage
        .written
        .into_iter()
        .map(|(key, value)| Write { key, value })
        .collect())
}

/// Decode the agent program's output as `T`.
pub(crate) fn decode<T: Decode>(bytes: &[u8]) -> Result<T, Fault> {
    T::decode(bytes)
        .map(|(value, _)| value)
        .map_err(|error| Fault::Agent(format!("undecodable output: {error:?}")))
}
