//! What the agent serves beside the actor ABI: precompiles, attestable
//! methods' kernels and random bytes.

use alloc::vec::Vec;

use vos_wire::abi::{Failure, cap, precompile};
use vos_wire::defaults;
use vos_wire::ids::ProgramHash;

use crate::machines::{self, ARGUMENTS, Exit, Machine};
use crate::refine::base::Meter;

/// Serve a machine's precompile call: its price checked first, so a call
/// the machine cannot pay takes nothing of the meter, as a failed charge
/// leaving the machine no gas; then the agent's serving taken from the
/// meter, and the call served.
pub(crate) fn serve_precompile(
    meter: &Meter,
    machine: &mut Machine,
    id: u64,
) -> Result<(), Failure> {
    let price = precompile::price(id).ok_or(Failure::Trapped)?;
    if machine.gas() < price {
        machine.set_gas(0);
        return Err(Failure::OutOfGas);
    }
    if !meter.take(defaults::PRECOMPILE_SERVING) {
        return Err(Failure::OutOfGas);
    }
    machine.precompile(id)
}

/// A kernel's run: its output, the bytes it read through its witness
/// input, and the gas it used.
pub(crate) struct KernelRun {
    pub output: Vec<u8>,
    pub witness_input: Vec<u8>,
    pub gas_used: u64,
}

/// Run an attestable method's kernel in its own machine with `gas`: laid
/// out with no arguments, its registers the loader's for none, it reads them
/// through its witness input from `input`; output by the halt convention, at
/// most `output` bytes, and no host calls but precompiles and the witness
/// input, which the agent serves. An input past a work result's cap is
/// refused.
pub(crate) fn kernel(
    meter: &Meter,
    program: &ProgramHash,
    input: &[u8],
    gas: u64,
    output: usize,
) -> Result<KernelRun, Failure> {
    if input.len() > cap::WORK_RESULT {
        return Err(Failure::Cap);
    }
    let mut machine = machines::pinned(&program.0, 0)?;
    machine.set_gas(gas);
    machine.set_register(7, ARGUMENTS);
    machine.set_register(8, 0);
    let mut read = 0;
    loop {
        match machine.invoke() {
            Exit::Host(precompile::WITNESS_INPUT) => {
                // Its price checked first, as a precompile's is: a call the
                // kernel cannot pay takes nothing of the meter.
                let rest = &input[read..];
                let (_, price) = machines::witness_read(machine.register(8), rest.len());
                if machine.gas() < price {
                    machine.set_gas(0);
                    return Err(Failure::OutOfGas);
                }
                if !meter.take(defaults::PRECOMPILE_SERVING) {
                    return Err(Failure::OutOfGas);
                }
                read += machine.witness_input(rest)?;
            }
            Exit::Host(id) if precompile::price(id).is_some() => {
                serve_precompile(meter, &mut machine, id)?;
            }
            Exit::Halt => {
                let gas_used = gas - machine.gas();
                let len = machine.register(8) as usize;
                if len > output {
                    return Err(Failure::Cap);
                }
                let output = machine.peek(machine.register(7), len).ok_or(Failure::Cap)?;
                return Ok(KernelRun {
                    output,
                    witness_input: input[..read].to_vec(),
                    gas_used,
                });
            }
            Exit::OutOfGas => return Err(Failure::OutOfGas),
            _ => return Err(Failure::Trapped),
        }
    }
}

/// [`Op::Random`]'s bytes: BLAKE2b-256 of `vos/random`, the seed, the step's
/// index and the draws before.
pub(crate) fn random(seed: &[u8; 32], step: u32, draw: u64) -> [u8; 32] {
    vos_pvm_precompiles::blake2b_hash::<32>(
        b"vos/random",
        &[seed, &step.to_le_bytes(), &draw.to_le_bytes()],
    )
}
