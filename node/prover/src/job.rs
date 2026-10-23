//! A statement's job in the prover's table: where its record is, the
//! statement, and how far it has come.

use vos_venue::vos_statement::{Statement, StatementId};
use vos_wire::ids::AgentId;
use vos_wire::result::Attest;
use vos_wire::vos_anchor::{MAX_ROOT_AGE_MS, WindowClock};
use vos_wire::{Decode, Encode, scale};

/// A job's code when the prover refuses its record: the kernel's re-run on
/// the record's witness does not return the record's output, public
/// arguments and roots, or its io-hash is not theirs. Past every venue's
/// codes.
pub const REFUSED_RERUN: u32 = 0x1_0001;

/// A job's code when its record names no kernel the prover can prove: its
/// program's blob does not derive a kernel, or the kernel does not run.
pub const REFUSED_KERNEL: u32 = 0x1_0002;

/// The times proving a statement may begin before it is refused
/// ([`REFUSED_KERNEL`]): a kernel whose proof panics or stops the node.
pub const MAX_ATTEMPTS: u32 = 3;

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
    /// Refused, with the venue's code, or [`REFUSED_RERUN`] or
    /// [`REFUSED_KERNEL`] by the prover.
    #[codec(index = 5)]
    Refused(u32),
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

/// A statement's job: the agent whose record made it, the record's place
/// in the agent's log, the record while it may be proved again, the
/// statement, and its state.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Job {
    pub agent: AgentId,
    /// The log index of the work result that recorded it.
    pub index: u64,
    /// The window whose cut the attest read at.
    pub window: u64,
    /// How many times proving it began: a prover that panics or stops the
    /// node on it gives up after [`MAX_ATTEMPTS`].
    pub attempts: u32,
    /// The record, kept until the job finishes: a proof another replica
    /// made may never arrive, and the statement is then proved here.
    pub attest: Option<Attest>,
    /// The statement's canonical encoding ([`Statement::encode`]).
    pub statement: Vec<u8>,
    pub state: State,
}

impl Job {
    /// A job of `attest`, recorded at `index` of `agent`'s log, stating
    /// `statement`, in `state`.
    pub fn new(
        agent: AgentId,
        index: u64,
        attest: Attest,
        statement: &Statement,
        state: State,
    ) -> Self {
        Self {
            agent,
            index,
            window: attest.window.unwrap_or(0),
            attempts: 0,
            attest: Some(attest),
            statement: statement.encode(),
            state,
        }
    }

    /// Its statement; `None` if its bytes do not decode.
    pub fn statement(&self) -> Option<Statement> {
        Statement::decode(&self.statement).ok()
    }

    /// Its statement's id; `None` if its bytes do not decode.
    pub fn id(&self) -> Option<StatementId> {
        self.statement().map(|statement| statement.id())
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
/// space's: `None` for a rootless statement, which no age ends.
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
