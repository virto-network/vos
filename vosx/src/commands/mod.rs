//! Per-subcommand implementations.
//!
//! - `run` — raw PVM/ELF execution, no space context.
//! - `space::*` — everything space-related: lifecycle (new,
//!   list, info, up, join, delete), program/agent management
//!   (publish, install, upgrade, uninstall, programs, agents),
//!   members, generic invoke (`call`), export.
//! - `dynamic` — `vosx <agent-or-extension> <method> [args]`.
//!   Schema-aware ergonomic surface that sits on the same
//!   `DaemonClient::invoke_dyn` path `space call` uses. Routing
//!   into this module is decided in `main` by peeking argv.

pub mod dynamic;
pub mod run;
pub mod space;
