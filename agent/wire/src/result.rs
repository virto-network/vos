//! A refine's output: the work result accumulate applies.

use alloc::vec::Vec;
use scale::{Decode, Encode};

use crate::ids::{AgentId, InstanceId, MethodId, ProgramHash, SessionId};

/// What one refine produced. Steps are in dispatch order; accumulate applies
/// their writes in that order. Inputs not covered by a step were not
/// dispatched (the refine's gas ran short) and wait for the next batch.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct WorkResult {
    /// The state version the refine read; accumulate applies the result
    /// only if it is still current (section 7.5).
    pub version: u64,
    pub time: u64,
    pub seed: [u8; 32],
    pub steps: Vec<Step>,
}

/// One input's step.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Step {
    /// The input was dispatched and consumed.
    #[codec(index = 0)]
    Ran(Run),
    /// Refine refused the input, with a code from [`crate::abi::refusal`],
    /// and consumed nothing. The leader batches only requests in their
    /// session's order in live sessions, and messages in their pair's
    /// order; refine checks again, and refuses rather than let accumulate
    /// advance a mark past a gap. Accumulate applies nothing for it; the
    /// node answers the sender.
    #[codec(index = 1)]
    Refused { input: InputRef, code: u32 },
}

/// A dispatched step: how it ended and its effects. A failed step has no
/// writes, messages or attests, but still consumes its input.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Run {
    pub input: InputRef,
    pub outcome: Outcome,
    /// Instances the step ran, in the order they first ran, with the gas
    /// each used: for metering, and for checking a refine's reads when
    /// another replica re-runs it.
    pub instances: Vec<InstanceGas>,
    pub writes: Vec<Write>,
    pub messages: Vec<Outgoing>,
    pub attests: Vec<Attest>,
    pub gas_used: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum InputRef {
    #[codec(index = 0)]
    Request { session: SessionId, sequence: u64 },
    #[codec(index = 1)]
    Message { from: AgentId, sequence: u64 },
    #[codec(index = 2)]
    Admin,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Outcome {
    /// The handler's reply.
    #[codec(index = 0)]
    Done(Vec<u8>),
    /// The step failed: a code from [`crate::abi::failure`] and detail
    /// bytes.
    #[codec(index = 1)]
    Failed { code: u32, detail: Vec<u8> },
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

/// A message for another agent, sent after the step commits.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Outgoing {
    pub to: AgentId,
    pub instance: InstanceId,
    pub method: MethodId,
    pub arguments: Vec<u8>,
}

/// An attestable method run in this step, unproven in slice 2, kept for
/// step 5's proofs. Its arguments may be private: work results stay in the
/// space's log (section 11.1) and are never published as they are.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Attest {
    pub program: ProgramHash,
    pub arguments: Vec<u8>,
    pub output: Vec<u8>,
}
