//! Why a batch, an apply or a query produced nothing, and the applied
//! state's reads that fail with it.

use vos_wire::Decode;
use vos_wire::ids::AgentId;
use vos_wire::records::unstored;

use crate::store::Snapshot;

/// Why a batch produced nothing.
#[derive(Debug)]
pub(crate) enum Fault {
    /// The agent program trapped, ran out of gas or answered nonsense:
    /// something in the batch may cause it.
    Agent(String),
    /// The node failed: a read, a backend or an executor. No input causes
    /// it, and it may pass.
    Infrastructure(String),
    /// A commit failed. fjall then refuses every later commit, so the node
    /// stops.
    Storage(String),
    /// The agent's state disagrees with its leader's: that agent stops.
    Invariant(String),
}

impl Fault {
    pub(crate) fn message(&self) -> &str {
        match self {
            Fault::Agent(message)
            | Fault::Infrastructure(message)
            | Fault::Storage(message)
            | Fault::Invariant(message) => message,
        }
    }
}

impl From<vos_pvm::refine::RefineError> for Fault {
    fn from(error: vos_pvm::refine::RefineError) -> Self {
        Fault::Infrastructure(format!("{error:?}"))
    }
}

/// A value of an agent's applied state; `None` when absent or unreadable.
pub(crate) fn read<T: Decode>(
    snapshot: &Snapshot,
    agent: AgentId,
    key: &[u8],
) -> Result<Option<T>, Fault> {
    let bytes = snapshot
        .get(agent, key)
        .map_err(|error| Fault::Infrastructure(error.to_string()))?;
    Ok(bytes.and_then(|bytes| T::decode(unstored(&bytes)?).ok().map(|(value, _)| value)))
}

/// An executor's answer, a panic there being the node's fault.
pub(crate) fn ran<T>(
    answer: Result<Result<T, Fault>, crate::executor::Panicked>,
) -> Result<T, Fault> {
    answer
        .unwrap_or_else(|panicked| Err(Fault::Infrastructure(format!("panicked: {}", panicked.0))))
}
