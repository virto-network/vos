//! A refine's output: the work result accumulate applies.

use alloc::vec::Vec;
use scale::{Decode, Encode};

use crate::abi::{Failure, Refusal, cap};
use crate::batch::Body;
use crate::ids::{AgentId, InstanceId, MapId, ProgramHash, SessionId, SessionRef};

/// What one refine produced. Steps are in dispatch order; accumulate applies
/// their writes in that order. Inputs not covered by a step were not
/// dispatched (the refine's gas ran short, or the next step would not fit
/// [`cap::WORK_RESULT`]) and wait for the next batch.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct WorkResult {
    /// The state version the refine read; accumulate applies the result
    /// only if it is still current.
    pub version: u64,
    pub time: u64,
    pub seed: [u8; 32],
    pub steps: Vec<Step>,
}

/// A [`WorkResult`]'s encoding, built a step at a time: each step's size
/// is known as it is added, and finishing re-encodes nothing.
pub struct ResultWriter {
    bytes: Vec<u8>,
    count: u32,
    count_at: usize,
}

impl ResultWriter {
    pub fn new(version: u64, time: u64, seed: [u8; 32]) -> Self {
        let mut bytes = Vec::new();
        version.encode_to(&mut bytes);
        time.encode_to(&mut bytes);
        seed.encode_to(&mut bytes);
        let count_at = bytes.len();
        0u32.encode_to(&mut bytes);
        Self {
            bytes,
            count: 0,
            count_at,
        }
    }

    /// Add `step` if the result stays within [`cap::WORK_RESULT`]; false,
    /// with nothing added, if it would not.
    pub fn push(&mut self, step: &Step) -> bool {
        let before = self.bytes.len();
        step.encode_to(&mut self.bytes);
        if self.bytes.len() > cap::WORK_RESULT {
            self.bytes.truncate(before);
            return false;
        }
        self.count += 1;
        true
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.bytes[self.count_at..self.count_at + 4].copy_from_slice(&self.count.to_le_bytes());
        self.bytes
    }
}

/// One input's step.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Step {
    /// The input was dispatched and consumed.
    #[codec(index = 0)]
    Ran(Run),
    /// Refine refused the input, and consumed nothing. The leader batches
    /// only requests in their session's order in live sessions, and
    /// messages in their pair's order; refine checks again, and refuses
    /// rather than let accumulate advance a mark past a gap. Accumulate
    /// applies nothing for it; the node answers the sender.
    #[codec(index = 1)]
    Refused { input: InputRef, code: Refusal },
    /// The sweep: the expiry rows refine found due, each a bucket and a
    /// session. Accumulate collects each session that has expired and
    /// moves the row of one active since.
    #[codec(index = 2)]
    Swept { due: Vec<(u64, SessionId)> },
}

/// A dispatched step: how it ended and its effects. A failed step has no
/// writes or attests, and no messages but a request's reply, but still
/// consumes its input.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Run {
    pub input: InputRef,
    pub outcome: Outcome,
    /// Instances the step ran, in the order they first ran, with the gas
    /// each used: for metering, and for checking a refine's reads when
    /// another replica re-runs it.
    pub instances: Vec<InstanceGas>,
    pub writes: Vec<Write>,
    /// Writes to committed maps, apart: accumulate marks each dirty for
    /// its map's root.
    pub committed: Vec<CommittedWrite>,
    pub messages: Vec<Outgoing>,
    pub attests: Vec<Attest>,
    pub gas_used: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum InputRef {
    #[codec(index = 0)]
    Request { session: SessionRef, sequence: u64 },
    #[codec(index = 1)]
    Message { from: AgentId, sequence: u64 },
    #[codec(index = 2)]
    Admin,
    #[codec(index = 3)]
    Ack { to: AgentId, sequence: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Outcome {
    /// The handler's reply.
    #[codec(index = 0)]
    Done(Vec<u8>),
    /// The step failed: why, and detail bytes.
    #[codec(index = 1)]
    Failed { code: Failure, detail: Vec<u8> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct InstanceGas {
    pub instance: InstanceId,
    pub gas: u64,
}

/// A write to the agent's state: a value, or (`None`) a deletion.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Write {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
}

/// A write to a committed map: its key already transformed (`key'`, as
/// the map's tree holds it), and a value, or (`None`) a deletion.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct CommittedWrite {
    pub map: MapId,
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
}

/// A message for another agent, sent after the step commits.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Outgoing {
    pub to: AgentId,
    pub body: Body,
}

/// An attestable method run in this step, kept so the run can be proven
/// later. Its arguments may be private: work results stay in the space's
/// log and are never published as they are.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Attest {
    pub program: ProgramHash,
    pub arguments: Vec<u8>,
    pub output: Vec<u8>,
}
