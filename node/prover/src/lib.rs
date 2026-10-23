//! The node's prover worker (`slice-6-on-chain.md`, 6.18).
//!
//! **The role** is the leader of the agent whose record it is: a node
//! proves and submits the statements of the agents it leads. Every replica
//! running a prover reads its own log into jobs, through its applied
//! index, and its log is compacted no further than that read (at most
//! 64k entries behind), so a new leader holds every record already and a
//! failover proves again at most the statement in flight.
//!
//! **Its table** is node-local ([`Jobs`]): each statement's job by id,
//! `queued | proving | proved(proof) | submitted | accepted |
//! refused(code) | dead` ([`State`]), and a watermark per agent, the last
//! index of its log read into jobs. A job is keyed by its statement's id,
//! so a record read twice makes one job.
//!
//! **For each attest at a window's cut** in an agent's log: the statement
//! it makes ([`Statement`](vos_venue::vos_statement::Statement): format 39,
//! its kernel's program id recomputed from the kernel's blob, the space,
//! the public arguments, the output and the roots) and its id. A statement
//! whose anchor would pass `MaxRootAge` by the venue's time before its
//! proof ends is dead, never proved (pin D's rule: time between parties is
//! the venue's). Otherwise the [`Prover`] re-runs the kernel on the
//! record's witness, refuses a run whose output or io-hash is not the
//! record's, and proves it: segments, leaves, folds and the masked wrap.
//! The proof is kept in the node's blob store, held there until its job
//! finishes, and the agent records it (`Input::Proven { window, id,
//! proof }`, through its leader). Once recorded and once the venue holds
//! its roots anchored, it is submitted through the space's
//! [`VenueClient`](vos_venue::VenueClient); a venue's repeat counts as
//! accepted, and a submission whose answer was lost goes again after 30 s,
//! the wait doubled each time. A prover that panics on a statement, or
//! stops the node, gives it up after three attempts.
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

mod job;
mod memory;
mod worker;

#[cfg(feature = "prove")]
pub mod masked;
#[cfg(feature = "prove")]
pub mod program;

pub use job::{Job, MAX_ATTEMPTS, REFUSED_KERNEL, REFUSED_RERUN, State, deadline};
pub use memory::MemoryJobs;
pub use worker::{Backlog, FORMAT, Host, Jobs, Options, ProveError, Prover, Stepped, Worker};
