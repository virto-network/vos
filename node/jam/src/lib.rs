//! An agent on JAM, from its builder's side.
//!
//! The builder holds the agent's whole keyspace under one tree, on disk
//! ([`Store`]). For each batch it simulates refine against the store,
//! recording every row it touches ([`Simulation`]), builds the package's
//! witness from them, names, as imports, the pages the batch's workflows
//! restore, by where earlier packages exported them, and fits the package
//! to a work package ([`builder`]). Once the chain holds the package's
//! root after, it commits the package to its store.
//!
//! The agent's programs are its service's preimages, derived from each
//! package's ELF as a VOS node derives them ([`programs`]).
//!
//! [`Emulated`] is a JAM node in process, DA included, so the whole
//! loop runs without one; [`live`] reaches a PolkaJam node.

mod admit;
pub mod builder;
mod chain;
mod da;
pub mod gas;
pub mod live;
pub mod programs;
mod simulate;
mod store;
mod witness;

use vos_pvm::ExitReason;
use vos_pvm::refine::RefineError;
use vos_wire::ids::WorkflowId;

pub use admit::admit;
pub use builder::{Attempt, Builder, Fate, Prepared, Taken};
pub use chain::{Chain, Emulated, Fault, Landed, Refined};
pub use da::{Da, Segments};
pub use simulate::{Runner, Simulation};
pub use store::{Exported, Pending, Store, View};

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("the agent's program: {0:?}")]
    Load(RefineError),
    #[error("refine stopped: {0:?}")]
    Refine(ExitReason),
    #[error("accumulate stopped: {0:?}")]
    Accumulate(ExitReason),
    #[error("refine's output is not a package's")]
    Output,
    #[error("the work result does not apply to the store")]
    Refused,
    /// The store's root is not the one the package was built on, or the
    /// chain holds another root than either.
    #[error("the roots do not continue the store's")]
    Root,
    /// The chain holds the root the package was built on.
    #[error("the chain refused the package")]
    Unaccumulated,
    #[error("the chain holds a root the store cannot reach")]
    Diverged,
    /// The batch was made again as often as the builder does: every
    /// attempt, none landed.
    #[error("the package did not land in {} attempts", .0.len())]
    Attempts(Vec<Attempt>),
    #[error("the exports are not the result and its pages")]
    Exports,
    #[error("the chain's work result is not the one simulated")]
    Result,
    #[error("a batch of one input does not fit a work package")]
    Unfit,
    /// DA lacks a page a workflow of the batch holds.
    #[error("DA lacks workflow {workflow}'s page {1}", workflow = .0.0)]
    Page(WorkflowId, u32),
    #[error("the store: {0}")]
    Store(String),
    /// A row of the store is not what it should be.
    #[error("the store holds {0} it should not")]
    Corrupt(&'static str),
    #[error("the tree: {0}")]
    Tree(#[from] vos_tree::Error),
    /// The JAM node, or its tools, failed.
    #[error("the JAM node: {0}")]
    Node(String),
    #[error("a call not signed by its session's key")]
    Signature,
    /// A package's ELF derives no programs.
    #[error("the package: {0}")]
    Package(String),
    /// A chain whose work packages' refine gas leaves a batch less than the
    /// least budget a VOS node refines with.
    #[error(
        "a work package's refine gas, {refine_gas}, leaves a batch less than the {least} a VOS \
         node refines with"
    )]
    RefineGas { refine_gas: u64, least: u64 },
    /// An install for another target than JAM, which a JAM service's
    /// agent runs on.
    #[error("an install for {0:?}: a JAM service takes installs for JAM alone")]
    Target(vos_wire::abi::cap::Target),
}

/// A store's error as a string: `Store` keeps `PartialEq`.
impl From<fjall::Error> for Error {
    fn from(error: fjall::Error) -> Self {
        Error::Store(error.to_string())
    }
}
