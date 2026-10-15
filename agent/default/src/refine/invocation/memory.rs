//! An actor's memory as the agent reads and writes it, at its price, and
//! the rows its keys name.

use alloc::vec::Vec;

use vos_wire::abi::{Failure, Rows, cap, price};
use vos_wire::ids::InstanceId;
use vos_wire::keys;

use crate::machines::Machine;

/// The agent-relative key of the row an operation names: its rows, by the
/// register `rows`, and the actor's key at `address`.
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

/// A row operation's key: its bytes, and the price of transforming them.
pub(crate) fn read_key(machine: &mut Machine, address: u64, len: u64) -> Result<Vec<u8>, Failure> {
    let key = read(machine, address, len, cap::KEY)?;
    if !machine.charge(key.len() as u64 * price::KEY_BYTE) {
        return Err(Failure::OutOfGas);
    }
    Ok(key)
}

/// The actor's bytes, at most `limit`: a longer buffer exceeds a cap and
/// an unreadable one traps.
pub(crate) fn read(machine: &mut Machine, address: u64, len: u64, limit: usize) -> Result<Vec<u8>, Failure> {
    let len = usize::try_from(len).map_err(|_| Failure::Cap)?;
    if len > limit {
        return Err(Failure::Cap);
    }
    if !machine.charge(len as u64 * price::PER_BYTE) {
        return Err(Failure::OutOfGas);
    }
    machine.peek(address, len).ok_or(Failure::Trapped)
}

/// Write `bytes` into the actor's memory through the machine's tracked
/// write, at their price.
pub(crate) fn write(machine: &mut Machine, address: u64, bytes: &[u8]) -> Result<(), Failure> {
    if !machine.charge(bytes.len() as u64 * price::PER_BYTE) {
        return Err(Failure::OutOfGas);
    }
    machine.write(address, bytes)
}

pub(crate) fn copy_out(
    machine: &mut Machine,
    bytes: &[u8],
    address: u64,
    offset: u64,
    capacity: u64,
) -> Result<(), Failure> {
    write(
        machine,
        address,
        &bytes[window(bytes.len(), offset, capacity)],
    )
}

/// What a copy out of `len` bytes takes, from `offset`, at most `capacity`.
pub(crate) fn window(len: usize, offset: u64, capacity: u64) -> core::ops::Range<usize> {
    let offset = usize::try_from(offset).unwrap_or(usize::MAX).min(len);
    let taken = usize::try_from(capacity)
        .unwrap_or(usize::MAX)
        .min(len - offset);
    offset..offset + taken
}
