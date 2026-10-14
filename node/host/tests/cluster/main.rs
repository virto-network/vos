//! Replicated agents on nodes in one process, joined through a hub or over
//! QUIC on localhost, each with its own clock: replication, large results,
//! messages, snapshots, membership changes, liveness and workflows.

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod common;
mod large_results;
mod liveness;
mod membership;
mod messages;
mod replication;
mod roots;
mod snapshots;
mod workflows;
