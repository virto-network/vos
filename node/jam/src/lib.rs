//! An agent on JAM, from its builder's side.
//!
//! The builder holds the agent's whole keyspace under one tree, on disk
//! ([`Store`]). For each batch it simulates refine against the store,
//! recording every row it touches ([`simulate`]), builds the package's
//! witness from them ([`witness`]), names, as imports, the pages the
//! batch's workflows restore, by where earlier packages exported them, and
//! fits the package to a work package ([`builder`]). Once the chain holds
//! the package's root after, it commits the package to its store.
//!
//! [`chain::Emulated`] is a JAM node in process, DA included, so the whole
//! loop runs without one; [`live`] reaches a PolkaJam node.

pub mod builder;
pub mod chain;
pub mod da;
pub mod gas;
pub mod live;
pub mod simulate;
pub mod store;
pub mod witness;

use vos_pvm::ExitReason;
use vos_pvm::refine::RefineError;
use vos_wire::ids::WorkflowId;

pub use builder::{Attempt, Builder, Fate, Prepared, Taken};
pub use chain::{Chain, Emulated, Fault, Landed, Refined};
pub use da::{Da, Segments, segment_root};
pub use simulate::{Runner, Simulation, simulate};
pub use store::{Exported, Pending, Store, View};
pub use witness::witness;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The program could not be loaded or run.
    Load(RefineError),
    /// Refine did not halt.
    Refine(ExitReason),
    /// Accumulate did not halt.
    Accumulate(ExitReason),
    /// Refine's output is not what it returns.
    Output,
    /// The work result does not apply to the store.
    Refused,
    /// The store's root is not the one the package was built on, or the
    /// chain holds another root than either.
    Root,
    /// The chain holds the root the package was built on: it refused it.
    Unaccumulated,
    /// The chain holds a root the store cannot reach.
    Diverged,
    /// The batch was made again as often as the builder does: every
    /// attempt, none landed.
    Attempts(Vec<Attempt>),
    /// The package's exports are not its pages and its work result.
    Exports,
    /// The work result the chain holds is not the one simulated.
    Result,
    /// Even a batch of one input does not fit a work package.
    Unfit,
    /// DA lacks a page a workflow of the batch holds.
    Page(WorkflowId, u32),
    /// The store failed.
    Store(String),
    /// A row of the store is not what it should be.
    Corrupt(&'static str),
    /// The tree refused a proof or an update.
    Tree(vos_tree::Error),
    /// The JAM node, or its tools, failed.
    Node(String),
    /// A call not signed by its session's key.
    Signature,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Load(error) => write!(f, "the agent's program: {error:?}"),
            Error::Refine(exit) => write!(f, "refine stopped: {exit:?}"),
            Error::Accumulate(exit) => write!(f, "accumulate stopped: {exit:?}"),
            Error::Output => f.write_str("refine's output is not a package's"),
            Error::Refused => f.write_str("the work result does not apply to the store"),
            Error::Root => f.write_str("the roots do not continue the store's"),
            Error::Unaccumulated => f.write_str("the chain refused the package"),
            Error::Diverged => f.write_str("the chain holds a root the store cannot reach"),
            Error::Attempts(attempts) => {
                write!(f, "the package did not land in {} attempts", attempts.len())
            }
            Error::Exports => f.write_str("the exports are not the result and its pages"),
            Error::Result => f.write_str("the chain's work result is not the one simulated"),
            Error::Unfit => f.write_str("a batch of one input does not fit a work package"),
            Error::Page(workflow, index) => {
                write!(f, "DA lacks workflow {}'s page {index}", workflow.0)
            }
            Error::Store(error) => write!(f, "the store: {error}"),
            Error::Corrupt(what) => write!(f, "the store holds {what} it should not"),
            Error::Tree(error) => write!(f, "the tree: {error}"),
            Error::Node(error) => write!(f, "the JAM node: {error}"),
            Error::Signature => f.write_str("a call not signed by its session's key"),
        }
    }
}

impl std::error::Error for Error {}

impl From<fjall::Error> for Error {
    fn from(error: fjall::Error) -> Self {
        Error::Store(error.to_string())
    }
}

impl From<vos_tree::Error> for Error {
    fn from(error: vos_tree::Error) -> Self {
        Error::Tree(error)
    }
}
