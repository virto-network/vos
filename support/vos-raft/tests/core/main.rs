//! The protocol core, driven directly: what it claims, applies and sends,
//! write by write. Cluster behaviour under faults is in `tests/simulated.rs`.

mod common;
mod configuration;
mod durability;
mod idle;
mod leader;
