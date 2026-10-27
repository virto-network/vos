//! Replicated agents on nodes in one process, joined through a hub or over
//! QUIC on localhost, each with its own clock: replication, large results,
//! messages, queries, snapshots, membership changes, liveness and
//! workflows; the space's representative and its anchoring; the prover
//! worker.

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod anchoring;
mod common;

/// The harness's bounds: the longest test takes about two minutes on a
/// loaded host, and its nodes prove with the model prover.
const BOUNDS: common::Bounds = common::Bounds {
    lifetime: std::time::Duration::from_secs(600),
    start_stop: std::time::Duration::from_secs(60),
    idle: Some(std::time::Duration::from_secs(300)),
};
mod cuts;
mod kreivo;
mod large_results;
mod liveness;
mod membership;
mod messages;
mod prover;
mod queries;
mod replication;
mod representative;
mod roots;
mod snapshots;
mod support;
mod workflows;
