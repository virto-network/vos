//! Replicated agents on nodes in one process, joined through a hub or over
//! QUIC on localhost, each with its own clock: replication, large results,
//! messages, queries, snapshots, membership changes, liveness and
//! workflows; the space's representative and the anchor keys it signs
//! with; the prover worker.

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod anchor_keys;
mod common;
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
