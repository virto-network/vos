//! Replicated agents on nodes in one process, joined through a hub or over
//! QUIC on localhost, each with its own clock: replication, large results,
//! messages, queries, snapshots, membership changes, liveness and
//! workflows.

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod common;
#[cfg(feature = "cuts")]
mod cuts;
mod large_results;
mod liveness;
mod membership;
mod messages;
mod queries;
mod replication;
mod roots;
mod snapshots;
mod workflows;
