//! Replicated agents on nodes in one process, joined through a hub or over
//! QUIC on localhost, each with its own clock: replication, messages,
//! snapshots, membership changes and liveness.

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod common;
mod liveness;
mod membership;
mod messages;
mod replication;
mod snapshots;
