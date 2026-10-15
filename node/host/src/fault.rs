//! Why a batch, an apply or a query produced nothing, and the applied
//! state's reads that fail with it.

use vos_wire::Decode;
use vos_wire::ids::{AgentId, Session, SessionId};
use vos_wire::keys;
use vos_wire::records::{SessionMark, unstored};

use crate::executor::Panicked;
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

impl From<fjall::Error> for Fault {
    fn from(error: fjall::Error) -> Self {
        Fault::Infrastructure(error.to_string())
    }
}

/// A panic on an executor is the node's fault.
impl From<Panicked> for Fault {
    fn from(panicked: Panicked) -> Self {
        Fault::Infrastructure(format!("panicked: {}", panicked.0))
    }
}

/// A value of an agent's applied state; `None` when absent or unreadable.
pub(crate) fn read<T: Decode>(
    snapshot: &Snapshot,
    agent: AgentId,
    key: &[u8],
) -> Result<Option<T>, Fault> {
    let bytes = snapshot.get(agent, key)?;
    Ok(bytes.and_then(|bytes| T::decode(unstored(&bytes)?).ok().map(|(value, _)| value)))
}

/// `session`'s id in `agent`'s applied state, and its mark there, if the
/// state holds the session.
pub(crate) fn session_mark(
    snapshot: &Snapshot,
    agent: AgentId,
    session: &Session,
) -> Result<Option<(SessionId, Option<SessionMark>)>, Fault> {
    let Some(id) = read::<SessionId>(snapshot, agent, &keys::session_index(session))? else {
        return Ok(None);
    };
    Ok(Some((
        id,
        read::<SessionMark>(snapshot, agent, &keys::session(id))?,
    )))
}
