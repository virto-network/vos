//! A refine's output: the work result accumulate applies.

use alloc::vec::Vec;
use scale::{Decode, Encode};

use crate::abi::{Failure, Refusal, cap};
use crate::batch::Body;
use crate::ids::{AgentId, InstanceId, MapId, ProgramHash, SessionId, SessionRef, WorkflowId};

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

/// A refine's output for a batch: the [`WorkResult`]'s encoding, then its
/// page section, `Vec<Vec<u8>>`: the LZ4 bytes of each page its steps store
/// ([`Run::pages`]), in the order they list them. Decoding the work result
/// reads none of the section, so the work result proper is the same
/// whatever carries its pages: this section on VOS, segments on JAM.
///
/// Built a step at a time: each step's size is known as it is added, and
/// finishing re-encodes nothing.
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

    /// The steps added so far.
    pub fn count(&self) -> u32 {
        self.count
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

    /// The output: the work result, then the pages `section` took.
    pub fn finish(mut self, section: PageSection) -> Vec<u8> {
        self.bytes[self.count_at..self.count_at + 4].copy_from_slice(&self.count.to_le_bytes());
        let pages = &section.bytes[..section.taken];
        self.bytes.reserve_exact(4 + pages.len());
        section.pages.encode_to(&mut self.bytes);
        self.bytes.extend_from_slice(pages);
        self.bytes
    }
}

/// A refine's page section as its steps fill it: each page a step stores,
/// framed as an item of `Vec<Vec<u8>>`, in one buffer reserved, at the
/// first, for the most pages a result holds ([`cap::RESULT_PAGES`]), so it
/// never grows or copies. The running step's pages lie past those taken,
/// until the batch takes the step or drops them.
#[derive(Default)]
pub struct PageSection {
    bytes: Vec<u8>,
    /// The bytes and the pages taken.
    taken: usize,
    pages: u32,
    /// The running step's pages, and whether one would pass the cap.
    running: u32,
    full: bool,
}

impl PageSection {
    /// The most pages a section holds.
    pub const PAGES: usize = cap::RESULT_PAGES / PAGE;

    pub const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            taken: 0,
            pages: 0,
            running: 0,
            full: false,
        }
    }

    /// Store a page of the running step: `write` puts its bytes, at most
    /// `max`, at the start of the slice it is given and returns how many.
    /// Where they lie, or `None` when the section would pass its cap, which
    /// keeps the step from being taken.
    pub fn store(
        &mut self,
        max: usize,
        write: impl FnOnce(&mut [u8]) -> usize,
    ) -> Option<core::ops::Range<usize>> {
        if self.full || (self.pages + self.running) as usize >= Self::PAGES {
            self.full = true;
            return None;
        }
        if self.bytes.capacity() == 0 {
            self.bytes.reserve_exact(Self::PAGES * (4 + max));
        }
        let at = self.bytes.len();
        self.bytes.resize(at + 4 + max, 0);
        let len = write(&mut self.bytes[at + 4..]).min(max);
        self.bytes[at..at + 4].copy_from_slice(&(len as u32).to_le_bytes());
        self.bytes.truncate(at + 4 + len);
        self.running += 1;
        Some(at + 4..at + 4 + len)
    }

    /// Whether the running step's pages all fit.
    pub fn fits(&self) -> bool {
        !self.full
    }

    /// Take the running step's pages: false, with them dropped, when one
    /// would have passed the cap.
    pub fn take(&mut self) -> bool {
        if self.full {
            self.drop_running();
            return false;
        }
        self.taken = self.bytes.len();
        self.pages += self.running;
        self.running = 0;
        true
    }

    /// Drop the running step's pages.
    pub fn drop_running(&mut self) {
        self.bytes.truncate(self.taken);
        self.running = 0;
        self.full = false;
    }

    /// The bytes of a page stored at `range`.
    pub fn page(&self, range: core::ops::Range<usize>) -> &[u8] {
        &self.bytes[range]
    }
}

/// A page's bytes, as a workflow's snapshot holds it.
pub const PAGE: usize = 4096;

/// A refine's output split: the work result, and its page section. A work
/// result with nothing after it stores no pages.
pub fn split_output(output: &[u8]) -> Option<(WorkResult, Vec<Vec<u8>>)> {
    let (result, used) = WorkResult::decode(output).ok()?;
    let rest = &output[used..];
    if rest.is_empty() {
        return Some((result, Vec::new()));
    }
    let (pages, section) = <Vec<Vec<u8>>>::decode(rest).ok()?;
    (section == rest.len()).then_some((result, pages))
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
    /// The sweep: the sessions among the rows of the due index the leader
    /// listed that refine found there and due, each the time its row is due
    /// at and the session. Accumulate collects each session that has
    /// expired and moves the row of one active since. The listed workflows'
    /// steps follow it.
    #[codec(index = 2)]
    Swept { due: Vec<(u64, SessionId)> },
}

/// A dispatched step: how it ended and its effects. A failed step has no
/// writes or attests, and no messages but a request's reply, but still
/// consumes its input; a failed workflow step still records the
/// workflow's end, with its rows and pages, and answers its owner.
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
    /// The pages of a workflow's snapshot the step stores or drops, apart
    /// from its writes: each stored page's bytes are in the output's page
    /// section ([`ResultWriter`]).
    pub pages: Vec<Page>,
    /// The gas the step's own machine used, its nested calls' included: a
    /// handler's at most its limit, a workflow's at most its limit for its
    /// effect-free code and its limit again from a unit's first effect.
    pub gas_used: u64,
}

/// A page of a workflow's snapshot: stored, by the hash of its bytes, or
/// dropped (`None`), back at its base, the program's image or zeros.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Page {
    pub workflow: WorkflowId,
    pub index: u32,
    pub hash: Option<[u8; 32]>,
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
    /// A workflow's step that no input resumes: its first, its deadline or
    /// its timer, or its collection once ended. Its row in the due index
    /// goes or moves with the step.
    #[codec(index = 4)]
    Due { workflow: WorkflowId },
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Outcome {
    /// The handler's reply.
    #[codec(index = 0)]
    Done(Vec<u8>),
    /// The step failed: why, and detail bytes.
    #[codec(index = 1)]
    Failed { code: Failure, detail: Vec<u8> },
    /// The request started a workflow, whose result its owner reads by its
    /// id.
    #[codec(index = 2)]
    Started(WorkflowId),
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
