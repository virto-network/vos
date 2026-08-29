//! Stable actor-execution contract of an agent runtime.
//!
//! The node supplies authenticated work and exact content-addressed program
//! availability. The runtime owns actor lookup, lane selection, inner-machine
//! host calls, and the next opaque runtime state.

use alloc::vec::Vec;

use super::{MethodMode, StateLane};
use crate::service::wire::Encoder;
use crate::service::{ActorId, BlobRef, DeploymentId, Hash, InvocationId, ProgramId};

pub const MAX_EXECUTION_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_EXECUTION_REPLY_BYTES: usize = 1024 * 1024;
pub const MAX_EXECUTION_STATE_BYTES: usize = 1024 * 1024;
pub const MAX_EXECUTION_PROGRAM_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_EXECUTION_BLOBS: usize = 4;

/// One content-addressed preimage made available to the runtime invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeBlob {
    pub reference: BlobRef,
    pub bytes: Vec<u8>,
}

/// Authenticated actor work delivered to one agent runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorInvocation {
    pub invocation: InvocationId,
    pub actor: ActorId,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub mode: MethodMode,
    pub message: Vec<u8>,
    pub availability: Vec<RuntimeBlob>,
    pub gas: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ActorExecutionStatus {
    Done = 0,
    Forbidden = 1,
    Panicked = 2,
    OutOfGas = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorExecutionReply {
    pub invocation: InvocationId,
    pub actor: ActorId,
    pub deployment: DeploymentId,
    pub lane: StateLane,
    pub status: ActorExecutionStatus,
    pub reply: Vec<u8>,
    pub gas_remaining: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorExecutionError {
    NotCreated,
    NotFound,
    Suspended,
    StaleDeployment,
    WrongProgram,
    UnsupportedMethod,
    MissingState,
    InvalidAvailability,
    InvalidInput,
    InvalidActorOutput,
    DivergentInvocation,
    ResultCapacity,
    UnsupportedHostCall(u32),
}

/// Complete runtime execution call. `state` is opaque to the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeExecutionCall {
    pub state: super::wire::RuntimeState,
    pub invocation: ActorInvocation,
    /// Exact content-addressed program resolved by the host from its durable
    /// package catalog. It is intentionally absent from [`ActorInvocation`]
    /// so callers cannot select executable bytes.
    pub actor_pvm: Vec<u8>,
}

/// Complete deterministic runtime execution result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeExecutionReturn {
    pub state: super::wire::RuntimeState,
    pub result: Result<ActorExecutionReply, ActorExecutionError>,
}

impl ActorInvocation {
    /// Stable identity of every execution-significant caller field. Program
    /// bytes are excluded because the host resolves them by `program` from
    /// its authenticated catalog.
    pub fn commitment(&self) -> Hash {
        let mut bytes = Vec::new();
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(&self.invocation.0);
        encoder.fixed(&self.actor.0);
        encoder.fixed(&self.deployment.0);
        encoder.fixed(&self.program.0);
        encoder.u8(match self.mode {
            super::MethodMode::Query => 0,
            super::MethodMode::LinearizableQuery => 1,
            super::MethodMode::Linear => 2,
            super::MethodMode::Merge => 3,
            super::MethodMode::Local => 4,
        });
        encoder.bytes(&self.message);
        encoder.list(&self.availability, |encoder, blob| {
            encoder.fixed(&blob.reference.hash.0);
            encoder.u64(blob.reference.len);
            encoder.bytes(&blob.bytes);
        });
        encoder.u64(self.gas);
        Hash::digest(b"vos/agent/invocation", &[&bytes])
    }

    pub fn validate(&self) -> Result<(), ActorExecutionError> {
        if self.invocation == InvocationId::ZERO
            || self.actor == ActorId::ZERO
            || self.deployment == DeploymentId::ZERO
            || self.program == ProgramId::ZERO
            || self.gas == 0
            || self.message.is_empty()
            || self.message.len() > MAX_EXECUTION_MESSAGE_BYTES
            || self.availability.len() > MAX_EXECUTION_BLOBS
            || self
                .availability
                .windows(2)
                .any(|pair| pair[0].reference.hash >= pair[1].reference.hash)
            || self.availability.iter().any(|blob| {
                blob.bytes.len() > MAX_EXECUTION_STATE_BYTES || !blob.reference.matches(&blob.bytes)
            })
        {
            return Err(ActorExecutionError::InvalidInput);
        }
        Ok(())
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn available(&self, reference: &BlobRef) -> Option<&[u8]> {
        self.availability
            .binary_search_by_key(&reference.hash, |blob| blob.reference.hash)
            .ok()
            .and_then(|index| {
                let blob = &self.availability[index];
                (blob.reference == *reference).then_some(blob.bytes.as_slice())
            })
    }
}

#[cfg(feature = "pvm")]
pub(crate) fn run_inner_actor(
    invocation: &ActorInvocation,
    actor_pvm: &[u8],
    actor_state: &[u8],
) -> Result<(ActorExecutionReply, Vec<u8>), ActorExecutionError> {
    use super::machine::{ActorMachine, InnerExit};
    use crate::abi::{error, hostcall};

    let mut machine =
        ActorMachine::load(actor_pvm, &[]).map_err(|_| ActorExecutionError::InvalidInput)?;
    let mut fetch = [actor_state, invocation.message.as_slice()].into_iter();
    let mut next_fetch = fetch.next();
    let mut gas = invocation.gas;

    loop {
        match machine.resume(gas) {
            InnerExit::Halt => {
                let registers = *machine.registers();
                let address = u32::try_from(registers[7])
                    .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
                let len = usize::try_from(registers[8])
                    .ok()
                    .filter(|len| *len <= MAX_EXECUTION_STATE_BYTES + MAX_EXECUTION_REPLY_BYTES + 5)
                    .ok_or(ActorExecutionError::InvalidActorOutput)?;
                let mut output = alloc::vec![0u8; len];
                machine
                    .read(address, &mut output)
                    .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
                return decode_actor_output(invocation, machine.gas_remaining(), output);
            }
            InnerExit::Panic | InnerExit::Fault(_) => {
                return Ok((
                    terminal_reply(
                        invocation,
                        ActorExecutionStatus::Panicked,
                        machine.gas_remaining(),
                    ),
                    actor_state.to_vec(),
                ));
            }
            InnerExit::OutOfGas => {
                return Ok((
                    terminal_reply(invocation, ActorExecutionStatus::OutOfGas, 0),
                    actor_state.to_vec(),
                ));
            }
            InnerExit::InvalidResult(_) => return Err(ActorExecutionError::InvalidActorOutput),
            InnerExit::Host(id) => {
                gas = machine.gas_remaining();
                let registers = *machine.registers();
                let (result0, result1) = match id {
                    hostcall::GAS => (gas, 0),
                    hostcall::FETCH => {
                        let address = u32::try_from(registers[7])
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        let capacity = usize::try_from(registers[8])
                            .ok()
                            .filter(|len| *len <= MAX_EXECUTION_STATE_BYTES)
                            .ok_or(ActorExecutionError::InvalidInput)?;
                        let item = next_fetch.take();
                        if let Some(item) = item {
                            let copied = item.len().min(capacity);
                            machine
                                .write(address, &item[..copied])
                                .map_err(|_| ActorExecutionError::InvalidInput)?;
                            next_fetch = fetch.next();
                            (item.len() as u64, 0)
                        } else {
                            (0, 0)
                        }
                    }
                    // The standard loader maps the program-declared heap up
                    // front. This call is therefore an accounting seam, not
                    // permission to mutate pages outside that declaration.
                    hostcall::GROW_HEAP => (error::HOST_OK, 0),
                    // Guest diagnostics never cross the deterministic runtime
                    // boundary. Validate the readable window, then discard it.
                    hostcall::DEBUG_WRITE => {
                        let address = u32::try_from(registers[7])
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        let len = usize::try_from(registers[8])
                            .ok()
                            .filter(|len| *len <= 8 * 1024)
                            .ok_or(ActorExecutionError::InvalidInput)?;
                        let mut discarded = alloc::vec![0u8; len];
                        machine
                            .read(address, &mut discarded)
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        (len as u64, 0)
                    }
                    other => return Err(ActorExecutionError::UnsupportedHostCall(other)),
                };
                let registers = machine.registers_mut();
                registers[7] = result0;
                registers[8] = result1;
            }
        }
    }
}

#[cfg(feature = "pvm")]
fn terminal_reply(
    invocation: &ActorInvocation,
    status: ActorExecutionStatus,
    gas_remaining: u64,
) -> ActorExecutionReply {
    ActorExecutionReply {
        invocation: invocation.invocation,
        actor: invocation.actor,
        deployment: invocation.deployment,
        lane: invocation
            .mode
            .write_lane()
            .expect("execution validated a write lane"),
        status,
        reply: Vec::new(),
        gas_remaining,
    }
}

#[cfg(feature = "pvm")]
fn decode_actor_output(
    invocation: &ActorInvocation,
    gas_remaining: u64,
    output: Vec<u8>,
) -> Result<(ActorExecutionReply, Vec<u8>), ActorExecutionError> {
    if output.len() < 5 {
        return Err(ActorExecutionError::InvalidActorOutput);
    }
    let state_len = u32::from_le_bytes(
        output[1..5]
            .try_into()
            .expect("the output length was checked above"),
    ) as usize;
    let state_end = 5usize
        .checked_add(state_len)
        .filter(|end| *end <= output.len())
        .ok_or(ActorExecutionError::InvalidActorOutput)?;
    if state_len > MAX_EXECUTION_STATE_BYTES || output.len() - state_end > MAX_EXECUTION_REPLY_BYTES
    {
        return Err(ActorExecutionError::InvalidActorOutput);
    }
    let status = match output[0] {
        crate::actors::STATUS_DONE => ActorExecutionStatus::Done,
        crate::actors::STATUS_FORBIDDEN => ActorExecutionStatus::Forbidden,
        crate::actors::STATUS_PANICKED => ActorExecutionStatus::Panicked,
        crate::actors::STATUS_OOG => ActorExecutionStatus::OutOfGas,
        // Continuations become a runtime-owned scheduling concern. Until the
        // standard runtime persists its portable machine snapshot, fail
        // closed instead of pretending a yielded transition completed.
        crate::actors::STATUS_YIELDED => return Err(ActorExecutionError::UnsupportedMethod),
        _ => return Err(ActorExecutionError::InvalidActorOutput),
    };
    let next_state = output[5..state_end].to_vec();
    let reply = output[state_end..].to_vec();
    Ok((
        ActorExecutionReply {
            invocation: invocation.invocation,
            actor: invocation.actor,
            deployment: invocation.deployment,
            lane: invocation
                .mode
                .write_lane()
                .expect("execution validated a write lane"),
            status,
            reply,
            gas_remaining,
        },
        next_state,
    ))
}
