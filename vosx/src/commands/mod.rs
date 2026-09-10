//! Per-subcommand implementations.
//!
//! - `build` / `new_project` — author portable AgentActor packages.
//! - `agent_runtime_pvm` — build and validate an agent-runtime PVM.
//! - `production_release` — package and independently verify the pinned
//!   production artifacts.
//! - `space::*` — the retained registry daemon and offline lifecycle surface.

pub mod agent_runtime_pvm;
pub mod build;
pub mod new_project;
pub mod production_release;
pub mod space;
pub mod zk;
