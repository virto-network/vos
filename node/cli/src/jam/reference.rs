//! A VOS node's refine and accumulate of an agent, in process: the
//! reference a JAM run of the same batches is checked against.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use vos_pvm::ExitReason;
use vos_pvm::accumulate_host::{AccumulateContext, ServiceStorage};
use vos_pvm::refine::{MemoryModel, PreparedProgram};
use vos_pvm::refine_host::{RefineContext, StateReader};
use vos_wire::abi::{cap, code};
use vos_wire::batch::{Batch, Work};
use vos_wire::jam::{AccumulateInput, Operand, RefineArgs};
use vos_wire::result::{WorkResult, split_output};
use vos_wire::{Encode, defaults};

use vos_jam::Error;

/// An agent on a VOS node: its program, the programs it may load, and its
/// state.
pub struct Vos {
    program: Arc<PreparedProgram>,
    service: u64,
    programs: HashMap<[u8; 32], Vec<u8>>,
    pub state: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Vos {
    pub fn new(
        program: Arc<PreparedProgram>,
        service: u64,
        programs: HashMap<[u8; 32], Vec<u8>>,
    ) -> Self {
        Self {
            program,
            service,
            programs,
            state: BTreeMap::new(),
        }
    }

    /// `batch` refined and accumulated: its work result, as the refine's
    /// output holds it.
    pub fn batch(&mut self, batch: &Batch) -> Result<WorkResult, Error> {
        let arguments = RefineArgs {
            core: 0,
            item: 0,
            service: self.service,
            payload: Work::Batch(batch.clone()).encode(),
            package_hash: [0; 32],
        }
        .encode();
        let gas = batch.budget + defaults::refine_start(batch.inputs.len(), arguments.len());
        let reader: Arc<dyn StateReader> = Arc::new(Snapshot(self.state.clone()));
        let programs = &self.programs;
        let invocation =
            RefineContext::load_prepared(&self.program, &arguments, gas, MemoryModel::Auto)
                .map_err(Error::Load)?
                .with_state(reader)
                .try_run_with_host(|id, machine| lookup(id, machine, programs))
                .map_err(Error::Load)?;
        if invocation.exit != ExitReason::Halt {
            return Err(Error::Refine(invocation.exit));
        }
        let output = invocation
            .output_bounded(cap::OUTPUT)
            .ok_or(Error::Output)?;
        let input = AccumulateInput::Operand(Operand {
            package_hash: [0; 32],
            segment_root: [0; 32],
            authorizer: [0; 32],
            payload_hash: [0; 32],
            gas_limit: 0,
            result: Ok(output.clone()),
            auth_trace: Vec::new(),
        })
        .encode();
        let inputs = [input];
        let accumulated = AccumulateContext::load(
            &self.program,
            0,
            self.service,
            &inputs,
            u64::MAX >> 1,
            &mut Storage(&mut self.state),
        )
        .map_err(Error::Load)?
        .try_run()
        .map_err(Error::Load)?;
        if accumulated.exit != ExitReason::Halt {
            return Err(Error::Accumulate(accumulated.exit));
        }
        split_output(&output)
            .map(|(result, _)| result)
            .ok_or(Error::Output)
    }
}

/// `historical_lookup` from `programs`; every other call the node does not
/// serve answers `WHAT`.
fn lookup(
    id: u64,
    machine: &mut vos_pvm::refine::Machine,
    programs: &HashMap<[u8; 32], Vec<u8>>,
) -> Result<(), ExitReason> {
    let registers = *machine.registers();
    if id != u64::from(vos_pvm::inner::gp_call::HISTORICAL_LOOKUP) {
        machine.registers_mut()[7] = code::WHAT;
        return Ok(());
    }
    let mut hash = [0u8; 32];
    if !machine
        .memory()
        .read_bytes_checked(registers[8] as u32, &mut hash)
    {
        return Err(ExitReason::Panic);
    }
    machine.registers_mut()[7] = match programs.get(&hash) {
        Some(blob) => {
            let offset = (registers[10] as usize).min(blob.len());
            let len = (registers[11] as usize).min(blob.len() - offset);
            if !machine
                .memory_mut()
                .write_bytes_checked(registers[9] as u32, &blob[offset..offset + len])
            {
                return Err(ExitReason::Panic);
            }
            blob.len() as u64
        }
        None => code::NONE,
    };
    Ok(())
}

struct Snapshot(BTreeMap<Vec<u8>, Vec<u8>>);

impl StateReader for Snapshot {
    fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.get(key).cloned()
    }

    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a> {
        Box::new(
            self.0
                .range(prefix.to_vec()..)
                .take_while(move |(key, _)| key.starts_with(prefix))
                .filter(move |(key, _)| after.is_none_or(|after| key.as_slice() > after))
                .map(|(key, value)| (key.clone(), value.clone())),
        )
    }
}

struct Storage<'a>(&'a mut BTreeMap<Vec<u8>, Vec<u8>>);

impl ServiceStorage for Storage<'_> {
    fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.get(key).cloned()
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) -> Option<usize> {
        let previous = match value {
            Some(value) => self.0.insert(key.to_vec(), value.to_vec()),
            None => self.0.remove(key),
        };
        previous.map(|value| value.len())
    }
}
