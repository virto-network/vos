//! The carrier audit (`proving.md` A.5) over three nodes proving with the
//! masked prover: a read at window 0's cut served, its statement proved,
//! recorded on every replica and accepted once `S_0` is anchored; then
//! every carrier the run produced, searched for what the prover built the
//! proof from ([`vos_checker::carriers`]).
//!
//! Carriers that leave the prover role: what the venue was sent (each
//! anchor and submission, as the model venue took it, and as Kreivo's
//! calls and the JAM statements service's items lay it out), every log
//! line of the process at every level, and the answers the client read.
//! Carriers within it: every frame between the nodes, every file each
//! node wrote, each agent's log entries and work results, and the prover
//! worker's table.
//!
//! Run alone in its process (`just test-carriers`): it captures the whole
//! process's logs.

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[allow(dead_code)]
#[path = "../cluster/common.rs"]
mod common;
#[allow(dead_code)]
#[path = "../cluster/support.rs"]
mod support;

mod audit;
