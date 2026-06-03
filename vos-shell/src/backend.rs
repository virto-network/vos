//! The backend-agnostic façade over a space's actor address book.
//!
//! The console engine never touches a transport directly — it goes through
//! [`SpaceClient`]. Two implementations exist (outside this crate):
//!
//! * `DaemonClientBackend` in `vosx` — the local console, over libp2p.
//! * `SshSpaceClient` in the ssh-console extension — over `ServiceCtx::ask_raw_as`.

use vos::abi::service::ServiceId;
use vos::metadata::ParsedMeta;
use vos::value::{Msg, Value};

/// One installed agent/extension as the console sees it. Drives the actor
/// browser and command/tab-completion discovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentInfo {
    /// The instance name used to address the agent (e.g. `counter`).
    pub instance_name: String,
    /// The program the instance runs (display only; may equal the name).
    pub program_name: String,
}

/// Failure modes a backend surfaces to the engine. The engine maps these
/// onto `nu_protocol::ShellError`s for rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    /// No reply — transport timed out or the daemon is gone.
    Unreachable,
    /// The daemon's auth gate refused the call (the `STATUS_FORBIDDEN`
    /// envelope). Surfaces as "permission denied" / a non-zero exit.
    Forbidden,
    /// No agent/extension by that name.
    NotFound(String),
    /// The reply could not be decoded (protocol mismatch).
    Decode(String),
    /// Anything else, carrying a human-readable message.
    Other(String),
}

impl core::fmt::Display for BackendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BackendError::Unreachable => write!(f, "daemon unreachable (no reply / timed out)"),
            BackendError::Forbidden => {
                write!(f, "permission denied: caller lacks the required role")
            }
            BackendError::NotFound(name) => write!(f, "no agent or extension named `{name}`"),
            BackendError::Decode(msg) => write!(f, "could not decode reply: {msg}"),
            BackendError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// True iff `bytes` is the 5-byte `STATUS_FORBIDDEN` envelope the daemon's
/// auth gate returns when refusing a call. Kept deliberately in sync with
/// the private `is_forbidden_envelope` in `vos` (`vos/src/lib.rs`): the
/// length and the four zero state-len bytes are both load-bearing so an
/// arbitrary 5-byte rkyv reply can't be mistaken for a refusal.
pub fn is_forbidden_envelope(bytes: &[u8]) -> bool {
    bytes.len() == 5 && bytes[0] == vos::STATUS_FORBIDDEN && bytes[1..5] == [0, 0, 0, 0]
}

/// Everything the console engine needs from a space. Implementors carry the
/// connection + the caller identity; the engine stays transport-agnostic.
pub trait SpaceClient: Send + Sync {
    /// Installed agents/extensions (drives the browser + completion).
    fn list_agents(&self) -> Result<Vec<AgentInfo>, BackendError>;

    /// Resolve a name to a target id. Implementors accept the same forms as
    /// `vosx` (instance name / `0xHEX` / `registry`).
    fn resolve_target(&self, name: &str) -> Result<ServiceId, BackendError>;

    /// The raw `.vos_meta` blob for an instance. Empty `Vec` = schema unknown
    /// (old binary / hash mismatch); the engine then falls back to permissive
    /// argument handling.
    fn raw_meta(&self, name: &str) -> Result<Vec<u8>, BackendError>;

    /// Decoded schema for an instance. Default impl decodes [`Self::raw_meta`].
    fn schema(&self, name: &str) -> Result<Option<ParsedMeta>, BackendError> {
        let blob = self.raw_meta(name)?;
        Ok(if blob.is_empty() {
            None
        } else {
            vos::metadata::decode(&blob)
        })
    }

    /// Invoke a dynamic message and return the decoded reply. Implementors
    /// MUST map the `STATUS_FORBIDDEN` envelope to [`BackendError::Forbidden`]
    /// (see [`is_forbidden_envelope`]) before decoding.
    fn invoke(&self, target: ServiceId, msg: &Msg) -> Result<Value, BackendError>;

    /// The caller identity/role this session acts as, if any. `None` for the
    /// local console (the daemon treats the operator as `Caller::System`); the
    /// SSH backend fills this from the authenticated device's member identity.
    fn caller(&self) -> Option<vos::Caller> {
        None
    }
}
