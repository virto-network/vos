//! The test harness of VOS actors.
//!
//! - [`World`]: a test's agents, each the default agent on a VOS node's
//!   hosts ([`node::Node`]), their actors installed, calls made by name at
//!   the world's clock, the messages between them delivered. What an
//!   actor's tests start from.
//! - [`personal`]: a personal agent as a home's node runs it, its calls
//!   and queries taken as ingress takes them.
//! - [`programs`]: the guest programs the repository builds, by name.
//! - [`model`]: the reference model of the default agent, a second
//!   implementation the differential tests hold the agent to.
//! - [`served`]: the rows a read at a window's cut is served.

pub mod model;
pub mod node;
pub mod personal;
pub mod programs;
pub mod served;
pub mod world;

pub use world::{World, answer};
