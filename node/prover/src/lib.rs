//! The node's prover worker (`proving.md` §6, "Venues in the node").
//!
//! **The role** is the leader of the agent whose record it is: a node
//! proves and submits the statements of the agents it leads. The records
//! of its attests at a window's cut are the agent's state
//! (`vos_wire::keys::attested`): every replica's apply writes each one a
//! work result makes, with its witness, and drops it once its roots age,
//! and a snapshot carries them. So every replica running a prover holds a
//! job of each, a new leader too, one that installed a snapshot among
//! them. A failover proves again the statement in flight and each whose
//! proof the old leader alone held, those the venue accepted among them:
//! no replica learns of an acceptance. A proof a replica ends once no
//! longer leading goes to the agent's leader to record.
//!
//! **Its table** is node-local ([`Jobs`]): each statement's job by id,
//! `queued | proving | proved(proof) | submitted | accepted |
//! refused(code) | dead` ([`State`]). A job is keyed by its statement's
//! id, so a record read twice makes one job. Each unfinished job's kernel
//! is held in the node's blob store; a record whose kernel is not here
//! waits for it, asked of the replicas and alerted, or ages out. An
//! unfinished job whose roots aged is dead, and the finished jobs of an
//! agent the node does not replicate go.

//! **For each attest at a window's cut** its agent records: the statement
//! it makes ([`Statement`](vos_venue::vos_statement::Statement):
//! `format::MASKED_WRAP`, its kernel's program id recomputed from the
//! kernel's blob, the space, the public arguments, the output and the
//! roots) and its id. A statement whose anchor would pass `MaxRootAge` by
//! the venue's time before its proof ends is dead, never proved (every
//! deadline between parties is the venue's time, `proving.md` §7).
//! Otherwise the [`Prover`] re-runs the kernel on the record's witness,
//! refuses a run whose output or io-hash is not the record's, and proves
//! it: segments, leaves, folds and the masked wrap. The proof is kept in
//! the node's blob store, held there until its job finishes, and the agent
//! records it (`Input::Proven`, through its leader).
//! Once recorded and once the venue holds its roots anchored, it is
//! submitted through the space's [`VenueClient`](vos_venue::VenueClient); a
//! venue's repeat counts as accepted, and a submission whose answer was
//! lost goes again after [`Options::retry`], the wait doubled each time;
//! a venue's failure to judge it, counted in its job, at most
//! [`MAX_RESUBMITS`] times. A prover that panics on a statement, or stops
//! the node, gives it up after [`MAX_ATTEMPTS`] attempts, a stop of the
//! node's own (its operator's) not counted; a panic's message is withheld
//! from standard error while a proof is made, its place printed.
//!
//! **Idempotent by statement id:** a restart finds a job it was proving
//! queued again and proves it once more; a submission it made counts once
//! at the venue. A statement its agent records proved by another replica
//! is submitted with the proof fetched from one, or, when none arrives in
//! time, proved again.
//!
//! `masked::MaskedProver` (feature `prove`) is the production prover, and
//! `program::program_id` a kernel's program id from its ELF, which `vos
//! program-id` prints.

mod internals;
mod job;
mod redact;
mod worker;

#[cfg(feature = "prove")]
pub mod masked;
#[cfg(feature = "prove")]
pub mod program;

pub use internals::{Internals, NodeProof};
pub use job::{
    Job, MAX_ATTEMPTS, MAX_RESUBMITS, REFUSED_KERNEL, REFUSED_RERUN, REFUSED_ROOTLESS,
    REFUSED_UNWITNESSED, State, deadline,
};
pub use worker::{
    Backlog, FORMAT, Host, Jobs, Options, ProveError, Prover, Record, Stepped, Worker, statement,
};

/// The gas a prover's re-run of a kernel starts with: a kernel's own limit
/// bounds the live run whose record it repeats, so this bounds nothing an
/// honest record needs. What a re-run has left shows its steps.
pub const RERUN_GAS: u64 = 1 << 32;
