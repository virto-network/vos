//! What the agent serves beside the actor ABI: precompiles, attestable
//! methods' kernels and random bytes.

use alloc::vec::Vec;

use vos_wire::Decode;
use vos_wire::abi::{Failure, cap, precompile};
use vos_wire::defaults;
use vos_wire::ids::ProgramHash;
use vos_wire::result::KernelReturn;

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
    if !meter.take(precompile::serving(id)) {
        return Err(Failure::OutOfGas);
    }
    machine.precompile(id)
}

/// A kernel's run: its output, the io-hash it left in φ9..φ12, the bytes it
/// read through its witness input, and the gas it used.
pub(crate) struct KernelRun {
    pub output: Vec<u8>,
    pub io_hash: [u8; 32],
    pub witness_input: Vec<u8>,
    pub gas_used: u64,
}

/// Run an attestable method's kernel in its own machine with `gas`: laid
/// out with no arguments, its registers the loader's for none, it reads them
/// through its witness input from `input`; output by the halt convention, at
/// most `output` bytes, and no host calls but the BLAKE2b precompile and the
/// witness input, which the agent serves. An input past a work result's cap is
/// refused. A failed run's error comes with the gas it used.
pub(crate) fn kernel(
    meter: &Meter,
    program: &ProgramHash,
    input: &[u8],
    gas: u64,
    output: usize,
) -> Result<KernelRun, (Failure, u64)> {
    if input.len() > cap::WORK_RESULT {
        return Err((Failure::Cap, 0));
    }
    let mut machine = machines::pinned(&program.0, 0).map_err(|code| (code.into(), 0))?;
    machine.set_gas(gas);
    run(meter, &mut machine, input, gas, output).map_err(|code| (code, gas - machine.gas()))
}

/// [`kernel`]'s run on `machine`, loaded with `gas`.
fn run(
    meter: &Meter,
    machine: &mut Machine,
    input: &[u8],
    gas: u64,
    output: usize,
) -> Result<KernelRun, Failure> {
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
            Exit::Host(precompile::BLAKE2B_COMPRESS) => {
                serve_precompile(meter, machine, precompile::BLAKE2B_COMPRESS)?;
            }
            Exit::Halt => {
                let gas_used = gas - machine.gas();
                let len = machine.register(8) as usize;
                if len > output {
                    return Err(Failure::Cap);
                }
                let output = machine.peek(machine.register(7), len).ok_or(Failure::Cap)?;
                let mut io_hash = [0u8; 32];
                for (word, register) in io_hash.chunks_exact_mut(8).zip(9..) {
                    word.copy_from_slice(&machine.register(register).to_le_bytes());
                }
                return Ok(KernelRun {
                    output,
                    io_hash,
                    witness_input: input[..read].to_vec(),
                    gas_used,
                });
            }
            Exit::OutOfGas => return Err(Failure::OutOfGas),
            _ => return Err(Failure::Trapped),
        }
    }
}

/// A kernel's return as its statement's parts, decoded whole, their
/// io-hash the one it left; `None` otherwise, a kernel's bug.
pub(crate) fn parts(returned: &[u8], io_hash: &[u8; 32]) -> Option<KernelReturn> {
    match KernelReturn::decode(returned) {
        Ok((parts, used)) if used == returned.len() && parts.io_hash() == *io_hash => Some(parts),
        _ => None,
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
