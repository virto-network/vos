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

/// Run an attestable method's kernel in its own machine: arguments in the
/// standard window, output by the halt convention, and no host calls but
/// precompiles, which the agent serves.
pub(crate) fn kernel(
    meter: &Meter,
    program: &ProgramHash,
    arguments: &[u8],
    gas: u64,
) -> Result<(Vec<u8>, u64), Failure> {
    let mut machine = machines::pinned(&program.0, 0)?;
    if !machine.map_read_only(ARGUMENTS, arguments.len() as u64, arguments) {
        return Err(Failure::Trapped);
    }
    machine.set_gas(gas);
    machine.set_register(7, ARGUMENTS);
    machine.set_register(8, arguments.len() as u64);
    loop {
        match machine.invoke() {
            Exit::Host(id) if precompile::price(id).is_some() => {
                serve_precompile(meter, &mut machine, id)?;
            }
            Exit::Halt => {
                let used = gas - machine.gas();
                let len = machine.register(8) as usize;
                if len > cap::REPLY {
                    return Err(Failure::Cap);
                }
                let output = machine.peek(machine.register(7), len).ok_or(Failure::Cap)?;
                return Ok((output, used));
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
