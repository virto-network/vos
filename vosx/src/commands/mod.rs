//! Per-subcommand implementations.
//!
//! - `build` / `new_project` — author portable AgentActor packages.
//! - `agent_runtime_pvm` — build and validate an agent-runtime PVM.
//! - `production_release` — package and independently verify the pinned
//!   production service/authority artifacts.
//! - `space::*` — everything space-related: lifecycle (new,
//!   list, info, up, join, delete), program/agent management
//!   (publish, install, upgrade, uninstall, programs, agents),
//!   members, generic invoke (`call`), export.
//! - `dynamic` — `vosx <agent-or-extension> <method> [args]`.
//!   Schema-aware ergonomic surface that sits on the same
//!   `DaemonClient::invoke_dyn` path `space call` uses. Routing
//!   into this module is decided in `main` by peeking argv.

pub mod agent_runtime_pvm;
pub mod build;
pub mod dynamic;
pub mod new_project;
pub mod production_release;
pub mod space;
pub mod zk;
