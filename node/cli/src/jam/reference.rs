//! A VOS node's refine and accumulate of an agent, in process: the
//! reference a JAM run of the same batches is checked against. It serves
//! `historical_lookup` as a node does ([`serve_lookup`]), from the agent's
//! preimages, and holds the agent's state in memory.

use std::collections::BTreeMap;
use std::sync::Arc;

use vos_pvm::ExitReason;
use vos_pvm::accumulate_host::AccumulateContext;
use vos_pvm::inner::gp_call::HISTORICAL_LOOKUP;
use vos_pvm::refine::{Machine, MemoryModel};
use vos_pvm::refine_host::{RefineContext, StateReader, serve_lookup};
use vos_wire::abi::surface::LOST;
use vos_wire::abi::{cap, code};
use vos_wire::batch::{Batch, Work};
use vos_wire::jam::{AccumulateInput, Operand};
use vos_wire::result::{WorkResult, split_output};
use vos_wire::{Encode, defaults};

use vos_jam::{Error, Runner};

/// An agent on a VOS node: its program, service and preimages, and its
/// state.
pub struct Vos {
    runner: Runner,
    pub state: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Vos {
    pub fn new(runner: Runner) -> Self {
        Self {
            runner,
            state: BTreeMap::new(),
        }
    }

    /// `batch` refined and accumulated: its work result, as the refine's
    /// output holds it.
    pub fn batch(&mut self, batch: &Batch) -> Result<WorkResult, Error> {
        let runner = &self.runner;
        let arguments = runner.arguments(&Work::Batch(batch.clone()).encode(), [0; 32]);
        let gas = batch.budget + defaults::refine_start(batch.inputs.len(), arguments.len());
        let reader: Arc<dyn StateReader> = Arc::new(self.state.clone());
        let invocation =
            RefineContext::load_prepared(&runner.program, &arguments, gas, MemoryModel::Auto)
                .map_err(Error::Load)?
                .with_state(reader)
                .try_run_with_host(|id, machine| serve(id, machine, runner))
                .map_err(Error::Load)?;
        if invocation.exit != ExitReason::Halt {
            return Err(Error::Refine(invocation.exit));
        }
        let output = invocation
            .output_bounded(cap::OUTPUT)
            .ok_or(Error::Output)?;
        let inputs = [AccumulateInput::Operand(Operand::new(output.clone())).encode()];
        let accumulated = AccumulateContext::load(
            &runner.program,
            0,
            runner.service,
            &inputs,
            u64::MAX >> 1,
            &mut self.state,
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

/// The calls a VOS node serves past the runtime: `historical_lookup` from
/// the agent's preimages, and the agent's report of lost state, which
/// stops the refine; every other answers `WHAT`.
fn serve(id: u64, machine: &mut Machine, runner: &Runner) -> Result<(), ExitReason> {
    match id {
        LOST => Err(ExitReason::HostCall(LOST)),
        id if id == u64::from(HISTORICAL_LOOKUP) => serve_lookup(machine, runner.service, |hash| {
            runner.preimages.preimage(runner.service, hash)
        }),
        _ => {
            machine.registers_mut()[7] = code::WHAT;
            Ok(())
        }
    }
}
