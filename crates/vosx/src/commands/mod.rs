//! Per-subcommand implementations.
//!
//! - `run` — raw PVM/ELF execution, no space context.
//! - `space::*` — everything space-related: lifecycle (new,
//!   list, info, up, join, delete), program/agent management
//!   (publish, install, upgrade, uninstall, programs, agents),
//!   members, generic invoke (`call`), export.

pub mod run;
pub mod space;
