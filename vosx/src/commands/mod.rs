//! Per-subcommand implementations.
//!
//! - `run` — raw PVM/ELF execution, no space context.
//! - `space::*` — everything space-related: lifecycle (new,
//!   list, info, up, join, delete), program/agent management
//!   (publish, install, upgrade, uninstall, programs, agents),
//!   members, generic invoke (`call`), export.
//! - `dev::*` — author + publish PVM actors from source held in a
//!   dev-project, wrapping the dev extension's compile/publish
//!   flow under `vosx dev new/compile/publish/log`.
//! - `ai::*` — drive the AI extension's `generate` handler from a
//!   CLI prompt. The extension loads the model lazily on first use.
//! - `dynamic` — `vosx <agent-or-extension> <method> [args]`.
//!   Schema-aware ergonomic surface that sits on the same
//!   `DaemonClient::invoke_dyn` path `space call` uses. Routing
//!   into this module is decided in `main` by peeking argv.

pub mod ai;
pub mod dev;
pub mod dynamic;
pub mod run;
pub mod space;
pub mod zk;
