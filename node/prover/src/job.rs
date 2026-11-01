//! A statement's job in the prover's table: where its record is, the
//! statement, and how far it has come.

use vos_venue::vos_statement::Statement;
use vos_wire::ids::AgentId;
use vos_wire::result::Attest;
use vos_wire::vos_anchor::{MAX_ROOT_AGE_MS, WindowClock};
use vos_wire::{Decode, Encode, scale};

/// Why a statement is refused for good: by the venue, with its code, or by
/// the prover. A job's row holds its code, a `u32`, the prover's past every
/// venue's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The venue's code: below the prover's.
    Venue(u32),
    /// The kernel's re-run on the record's witness does not return the
    /// record's output, public arguments and roots, or its io-hash is not
    /// theirs.
    Rerun,
    /// The record names no kernel the prover can prove: its program's blob
    /// does not derive a kernel, or the kernel does not run.
    Kernel,
    /// The record at a cut states no root: no venue takes it.
    Rootless,
    /// The record holds no witness: no re-run proves it.
    Unwitnessed,
}

impl Refusal {
    const RERUN: u32 = 0x1_0001;
    const KERNEL: u32 = 0x1_0002;
    const ROOTLESS: u32 = 0x1_0003;
    const UNWITNESSED: u32 = 0x1_0004;

    /// Its code, as a job's row holds it.
    pub fn code(self) -> u32 {
        match self {
            Self::Venue(code) => code,
            Self::Rerun => Self::RERUN,
            Self::Kernel => Self::KERNEL,
            Self::Rootless => Self::ROOTLESS,
            Self::Unwitnessed => Self::UNWITNESSED,
        }
    }

    /// The refusal a job's row's code names.
    pub fn of(code: u32) -> Self {
        match code {
            Self::RERUN => Self::Rerun,
            Self::KERNEL => Self::Kernel,
            Self::ROOTLESS => Self::Rootless,
            Self::UNWITNESSED => Self::Unwitnessed,
            code => Self::Venue(code),
        }
    }
}

impl Encode for Refusal {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.code().encode_to(buf);
    }
}

impl Decode for Refusal {
    fn decode(data: &[u8]) -> Result<(Self, usize), vos_wire::DecodeError> {
        u32::decode(data).map(|(code, used)| (Self::of(code), used))
    }
}

/// The times proving a statement may begin before it is refused
/// ([`Refusal::Kernel`]): a kernel whose proof panics or stops the node.
pub const MAX_ATTEMPTS: u32 = 3;

/// The times a statement goes again after a venue failed to judge it
/// (from [`vos_venue::UNJUDGED_FROM`]: on JAM, refine out of gas, a panic,
/// an undecodable verdict, each likely the same the next time), then
/// refused with that code.
pub const MAX_RESUBMITS: u32 = 4;

/// How far a statement's job has come.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum State {
    /// To be proved.
    #[codec(index = 0)]
    Queued,
    /// Being proved: a restart finds it so and proves it again.
    #[codec(index = 1)]
    Proving,
    /// Proved, its final proof the blob `proof` (its BLAKE2b-256): to be
    /// recorded in the agent, then submitted once its roots are anchored.
    #[codec(index = 2)]
    Proved { proof: [u8; 32] },
    /// Handed to the venue: a restart submits it again, and the venue's
    /// repeat check counts it once.
    #[codec(index = 3)]
    Submitted { proof: [u8; 32] },
    /// The venue holds it accepted: accepted now, or before (a repeat).
    #[codec(index = 4)]
    Accepted,
    /// Refused, by the venue or the prover.
    #[codec(index = 5)]
    Refused(Refusal),
    /// Its anchor passed `MaxRootAge` by the venue's time, or would before
    /// its proof ends: no venue takes it.
    #[codec(index = 6)]
    Dead,
}

impl State {
    /// Whether nothing more happens to it.
    pub fn finished(self) -> bool {
        matches!(self, Self::Accepted | Self::Refused(_) | Self::Dead)
    }

    /// The proof it holds, once proved and until accepted.
    pub fn proof(self) -> Option<[u8; 32]> {
        match self {
            Self::Proved { proof } | Self::Submitted { proof } => Some(proof),
            _ => None,
        }
    }
}

/// A statement's job: the agent whose record made it, the record's
/// digest, the record while it may be proved again, the statement, and its
/// state.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Job {
    pub agent: AgentId,
    /// The digest of the attest's record ([`Attest::digest`]), which names
    /// it in its agent's state (`vos_wire::keys::attested`).
    pub attested: [u8; 32],
    /// The window whose cut the attest read at.
    pub window: u64,
    /// How many times proving it began, a stop of the node's own apart: a
    /// prover that panics or stops the node on it gives up after
    /// [`MAX_ATTEMPTS`].
    pub attempts: u32,
    /// How many times it went again after a venue failed to judge it,
    /// bounded by [`MAX_RESUBMITS`].
    pub resubmits: u32,
    /// The record, kept until the job finishes: a proof another replica
    /// made may never arrive, and the statement is then proved here.
    pub attest: Option<Attest>,
    /// The statement's canonical encoding ([`Statement::encode`]).
    pub statement: Vec<u8>,
    pub state: State,
}

impl Job {
    /// A job of `agent`'s record `attest`, whose digest is `attested`,
    /// stating `statement`, in `state`.
    pub fn new(
        agent: AgentId,
        attested: [u8; 32],
        attest: Attest,
        statement: &Statement,
        state: State,
    ) -> Self {
        Self {
            agent,
            attested,
            window: attest.window.unwrap_or(0),
            attempts: 0,
            resubmits: 0,
            attest: Some(attest),
            statement: statement.encode(),
            state,
        }
    }

    /// Its statement; `None` if its bytes do not decode.
    pub fn statement(&self) -> Option<Statement> {
        Statement::decode(&self.statement).ok()
    }

    /// When no venue takes it any more: its statement's [`deadline`], or,
    /// for one that states no root, `MaxRootAge` past its window's cut.
    pub fn deadline(&self, clock: &WindowClock) -> Option<u64> {
        self.statement()
            .and_then(|statement| deadline(&statement, clock))
            .or_else(|| {
                let boundary = clock.boundary(self.window)?;
                Some(boundary.saturating_add(MAX_ROOT_AGE_MS))
            })
    }

    /// The earliest window its statement reads a root at; none for one that
    /// does not decode.
    pub(crate) fn earliest_window(&self) -> Option<u64> {
        self.statement()
            .and_then(|statement| statement.roots.iter().map(|root| root.window).min())
    }

    /// Moved to `state`, its record dropped once it finishes.
    pub fn to(mut self, state: State) -> Self {
        self.state = state;
        if state.finished() {
            self.attest = None;
        }
        self
    }
}

/// The venue time by which every root `statement` reads stops being
/// anchored, each `MaxRootAge` past its window's boundary on `clock`, the
/// space's: `None` for a rootless statement, which no venue takes.
pub fn deadline(statement: &Statement, clock: &WindowClock) -> Option<u64> {
    statement
        .roots
        .iter()
        .map(|root| {
            clock
                .boundary(root.window)
                .map_or(0, |boundary| boundary.saturating_add(MAX_ROOT_AGE_MS))
        })
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refused job's row holds its code as a `u32`, the prover's past
    /// every venue's, and reads back as the refusal it was.
    #[test]
    fn a_refusal_is_its_code_in_the_row() {
        for (refusal, code) in [
            (Refusal::Venue(3), 3u32),
            (Refusal::Venue(0x1001), 0x1001),
            (Refusal::Rerun, 0x1_0001),
            (Refusal::Kernel, 0x1_0002),
            (Refusal::Rootless, 0x1_0003),
            (Refusal::Unwitnessed, 0x1_0004),
        ] {
            let row = State::Refused(refusal).encode();
            assert_eq!(row, [&[5][..], &code.to_le_bytes()].concat());
            assert_eq!(State::decode_exact(&row), Some(State::Refused(refusal)));
        }
    }
}
