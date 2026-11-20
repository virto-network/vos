//! The personal space's test doubles, one of each, shared by the light
//! node's tests, the facility's and the tools (the `testing` feature):
//!
//! - [`Phone`]: the user and their phone's keys, the [`Prompts`] every
//!   flow asks, each key reference honoured (an alias never made, no key);
//! - [`World`]: the spaces a phone reaches, in process, behind a gateway
//!   serving `vos-api` over SSH on each stream the Tor client dials, the
//!   homes' personal agents [`vos_testkit::personal::Agent`]s, every proof
//!   checked as ingress checks it, a phone's process killed at any request;
//! - [`Reach`]: a phone's [`Host`] over that world.
//!
//! [`Prompts`]: crate::space::Prompts
//! [`Host`]: crate::space::Host

mod held;
mod phone;
mod reach;
pub mod world;

pub use phone::{Phone, hmac};
pub use reach::Reach;
pub use world::{
    Death, Kernels, Loopback, Seen, Step, World, address, onion_of, personal_package, policy,
    program, wall,
};
