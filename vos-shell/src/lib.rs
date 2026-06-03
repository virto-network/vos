//! `vos-shell` — a sandboxed [nushell]-backed console engine for VOS spaces.
//!
//! Users discover and invoke the actors of a space like programs of an OS,
//! driving real nu-script syntax (pipelines, variables, control flow) — but
//! with NO filesystem / network / external commands. The only side-effecting
//! surface is the set of actor-backed commands, each of which still passes
//! through the daemon's own auth gate.
//!
//! The engine is backend-agnostic: it talks to a space only through the
//! [`SpaceClient`] trait. The local console (`vosx space console`) implements
//! it over `DaemonClient`; the SSH transport implements it over
//! `ServiceCtx::ask_raw_as`. Nothing in this crate is libp2p- or
//! transport-aware.
//!
//! [nushell]: https://www.nushell.sh/

pub mod actor_cmd;
pub mod backend;
pub mod discovery;
pub mod engine;
pub mod sandbox;
pub mod tui;
pub mod value_bridge;

pub use backend::{AgentInfo, BackendError, SpaceClient, is_forbidden_envelope};
pub use discovery::SchemaCache;
pub use engine::{ConsoleEngine, EvalResult};
pub use tui::run as run_tui;
