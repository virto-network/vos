//! Per-subcommand implementations.
//!
//! - `run` — signed `.vos` v2 package execution, no space context.
//! - `service_pvm` — build and validate the protocol infrastructure PVM.
//! - `space::*` — everything space-related: lifecycle (new,
//!   list, info, up, join, delete), program/agent management
//!   (publish, install, upgrade, uninstall, programs, agents),
//!   members, generic invoke (`call`), export.
//! - `dynamic` — `vosx <agent-or-extension> <method> [args]`.
//!   Schema-aware ergonomic surface that sits on the same
//!   `DaemonClient::invoke_dyn` path `space call` uses. Routing
//!   into this module is decided in `main` by peeking argv.

pub mod build;
pub mod dynamic;
pub mod new_project;
pub mod run;
pub mod service_pvm;
pub mod space;
pub mod zk;
