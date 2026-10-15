//! An actor's memory as the model reads and writes it, at its price, the
//! rows its keys name, and what is served beside the actor ABI.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use vos_pvm::ExitReason;
use vos_pvm::refine::Machine;
use vos_wire::abi::{Failure, Rows, cap, price};
use vos_wire::ids::InstanceId;
use vos_wire::keys;
use vos_wire::records::unversioned;

/// The value applied state holds under `key`: in a committed map's value
/// row, without the version that wrote it.
pub(crate) fn held(key: &[u8], value: &[u8]) -> Result<Vec<u8>, Failure> {
    if keys::is_committed(key) {
        Ok(unversioned(value).ok_or(Failure::Trapped)?.1.to_vec())
    } else {
        Ok(value.to_vec())
    }
}

/// The agent-relative key of the row an operation names, by the register
/// `rows` and the actor's key at `address`/`len`.
pub(crate) fn row(
    machine: &mut Machine,
    instance: InstanceId,
    rows: u64,
    address: u64,
    len: u64,
) -> Result<Vec<u8>, Failure> {
    let key = read_key(machine, address, len)?;
    let rows = Rows::from_register(rows).ok_or(Failure::Trapped)?;
    keys::row(instance, rows, &key)
}

/// A row operation's key at `address`: its bytes, with the price of its
/// transform charged after their copy.
pub(crate) fn read_key(machine: &mut Machine, address: u64, len: u64) -> Result<Vec<u8>, Failure> {
    let key = read(machine, address, len, cap::KEY)?;
    if machine.charge(key.len() as u64 * price::KEY_BYTE) {
        Ok(key)
    } else {
        Err(Failure::OutOfGas)
    }
}

/// Serve a precompile as the agent serves its machines': the node's price,
/// then its work on the actor's memory.
pub(crate) fn precompile(machine: &mut Machine, id: u64) -> Result<(), Failure> {
    if !machine.charge(vos_pvm::precompile::price(id).unwrap_or(0)) {
        return Err(Failure::OutOfGas);
    }
    let registers = *machine.registers();
    vos_pvm::precompile::execute(id, &registers, machine.memory_mut())
        .map(|_| ())
        .ok_or(Failure::Trapped)
}

/// Run an attestable method's kernel: arguments in the standard window,
/// output by the halt convention, and no host calls but precompiles. Its
/// output and gas used.
pub(crate) fn kernel(
    program: &[u8],
    arguments: &[u8],
    gas: u64,
) -> Result<(Vec<u8>, u64), Failure> {
    let mut machine = Machine::load(program, arguments, gas).map_err(|_| Failure::Trapped)?;
    loop {
        match machine.try_resume().map_err(|_| Failure::Trapped)? {
            ExitReason::HostCall(id) if vos_pvm::precompile::is_precompile(id) => {
                precompile(&mut machine, id)?;
            }
            ExitReason::Halt => {
                let invocation = machine.finish(ExitReason::Halt);
                let output = invocation.output_bounded(cap::REPLY).ok_or(Failure::Cap)?;
                return Ok((output, invocation.gas_used));
            }
            ExitReason::OutOfGas => return Err(Failure::OutOfGas),
            _ => return Err(Failure::Trapped),
        }
    }
}

/// The 32 bytes of [`Op::Random`]: BLAKE2b-256 of the batch seed, the step's
/// index and how many the step drew before.
pub(crate) fn random(seed: &[u8; 32], step: u32, draw: u64) -> [u8; 32] {
    Blake2b::<U32>::new()
        .chain_update(b"vos/random")
        .chain_update(seed)
        .chain_update(step.to_le_bytes())
        .chain_update(draw.to_le_bytes())
        .finalize()
        .into()
}

/// The actor's bytes at `address`, at most `limit` of them; an unreadable
/// buffer traps and a longer one exceeds a cap.
pub(crate) fn read(
    machine: &mut Machine,
    address: u64,
    len: u64,
    limit: usize,
) -> Result<Vec<u8>, Failure> {
    let len = usize::try_from(len).map_err(|_| Failure::Cap)?;
    if len > limit {
        return Err(Failure::Cap);
    }
    price_bytes(machine, len)?;
    let mut bytes = vec![0; len];
    if len > 0 {
        let address = u32::try_from(address).map_err(|_| Failure::Trapped)?;
        if !machine.memory().is_readable(address, len)
            || !machine.memory().read_bytes_checked(address, &mut bytes)
        {
            return Err(Failure::Trapped);
        }
    }
    Ok(bytes)
}

pub(crate) fn write(machine: &mut Machine, address: u64, bytes: &[u8]) -> Result<(), Failure> {
    price_bytes(machine, bytes.len())?;
    if bytes.is_empty() {
        return Ok(());
    }
    let address = u32::try_from(address).map_err(|_| Failure::Trapped)?;
    if machine.memory_mut().write_bytes_checked(address, bytes) {
        Ok(())
    } else {
        Err(Failure::Trapped)
    }
}

/// Copy `bytes[offset..]`, at most `capacity` of them, to `address`.
pub(crate) fn copy_out(
    machine: &mut Machine,
    bytes: &[u8],
    address: u64,
    offset: u64,
    capacity: u64,
) -> Result<(), Failure> {
    let offset = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    let len = usize::try_from(capacity)
        .unwrap_or(usize::MAX)
        .min(bytes.len() - offset);
    write(machine, address, &bytes[offset..offset + len])
}

pub(crate) fn price_bytes(machine: &mut Machine, len: usize) -> Result<(), Failure> {
    if machine.charge(len as u64 * price::PER_BYTE) {
        Ok(())
    } else {
        Err(Failure::OutOfGas)
    }
}
