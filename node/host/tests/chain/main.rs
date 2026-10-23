//! The end to end on chain (`slice-6-on-chain.md` 6.21): three nodes of a
//! space running `balance`, the window actor, the reader and the
//! representative, each proving with the masked prover, anchor first at
//! Kreivo, as its spaces pallet's mock models it, then migrate to the JAM
//! statements service on a PolkaJam testnet.
//!
//! - **Kreivo:** the space registered and its authorities added by the
//!   pallet's calls; each node anchors and submits through its
//!   `KreivoVenue`, the space's sovereign account paying within its
//!   budget; a balance statement at a window's cut accepted.
//! - **The migration** at window k: the space registered at the JAM
//!   service from k and migrated away from the mock from k; the nodes'
//!   venue moved to the service once window k − 1 is anchored at the mock.
//! - **JAM:** windows k to k + 2 anchored, a balance and a window
//!   statement read at each cut, proved masked and accepted; the first of
//!   them refused at the mock (`0x5`). The reader's rootless statements: a
//!   venue-bound one accepted at the service and refused at a second
//!   deployment of it, another venue (`0x7`), an unbound one accepted at
//!   both. Then the chain's clock moves past `MaxRootAge` and each
//!   accepted rootless statement, replayed, is refused as a repeat (`0x6`),
//!   a rooted one as unanchored (`0x5`).
//! - **The carrier audit** (`vos_checker::carriers`) over the whole run:
//!   what each venue's client was asked to send, every work package the
//!   JAM clients sent with its extrinsics and work report, the mock's
//!   signed extrinsics, both venues' anchor chains, the testnet's log and
//!   chain, every frame between the nodes, each node's store and disk, the
//!   process's logs and standard error (`collect`).
//! - **Measured:** each statement's latency from its window's boundary to
//!   its acceptance, against pin D's `L/2 + D + t_prove + inclusion` and
//!   the gate `L + D + t_prove + 30 s`; the refine gas of each statement at
//!   the service; the deposits and fees the mock charged the sovereign
//!   account; the prover's throughput.
//!
//! It runs against the testnet `just e2e-chain` starts, alone in its
//! process, which it captures whole.

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[allow(dead_code)]
#[path = "../cluster/common.rs"]
mod common;
#[allow(dead_code)]
#[path = "../cluster/cuts.rs"]
mod cuts;
#[allow(dead_code)]
#[path = "../cluster/representative.rs"]
mod representative;

mod agents;
mod collect;
mod jam;
mod kernels;
mod kreivo;
mod measure;
mod record;
mod run;
mod venues;
