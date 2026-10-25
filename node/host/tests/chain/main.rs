//! The end to end on chain: two spaces of three nodes each running
//! `balance`, the window actor, the reader and the representative, each
//! proving with the masked prover; one anchoring at Kreivo, as its spaces
//! pallet's mock models it, the other at the JAM statements service on a
//! PolkaJam testnet.
//!
//! - **Kreivo:** the space registered from the chain's next window and its
//!   authorities added by the pallet's calls; each node anchors and submits
//!   through its `KreivoVenue`, the space's sovereign account paying within
//!   its budget; a balance statement at a window's cut accepted.
//! - **JAM:** the other space registered at the service by a founder's
//!   signature, from its next window; three windows anchored, a balance and
//!   a window statement read at each cut, proved masked and accepted. The
//!   first of them refused where its space's roots are not anchored: at
//!   Kreivo and at a second deployment of the service (`0x5`). The
//!   reader's rootless `ordered`, its program pinned, refused at the
//!   service (`0x4`): a venue judges rooted statements alone. Then the
//!   chain's clock moves past `MaxRootAge` and the first statement,
//!   replayed, is refused as unanchored (`0x5`).
//! - **The carrier audit** (`vos_checker::carriers`) over the whole run:
//!   what each venue's client was asked to send, every work package the
//!   JAM clients sent with its extrinsics and work report, the mock's
//!   signed extrinsics, both venues' anchor chains, the testnet's log and
//!   chain, every frame between the nodes, each node's store and disk, the
//!   process's logs and standard error (`collect`).
//! - **Measured:** each statement's latency from its window's boundary to
//!   its acceptance, against `proving.md` §7's
//!   `L/2 + D + t_prove + inclusion` and the gate `L + D + t_prove + 30 s`;
//!   the refine gas of each statement at the service; the deposits and fees
//!   the mock charged the sovereign account; the prover's throughput.
//!
//! It runs against the testnet `just e2e-chain` starts, alone in its
//! process, which it captures whole.

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[allow(dead_code)]
#[path = "../cluster/common.rs"]
mod common;
#[allow(dead_code)]
#[path = "../cluster/support.rs"]
mod support;

mod agents;
mod collect;
mod jam;
mod kernels;
mod kreivo;
mod measure;
mod record;
mod run;
mod venues;
