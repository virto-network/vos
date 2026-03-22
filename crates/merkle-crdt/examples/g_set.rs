//! # Grow-Only Set (G-Set) — Decentralized Collaborative Tagging
//!
//! Demonstrates the simplest and most natural Merkle-CRDT: a grow-only set where
//! multiple independent replicas add items without any coordination.
//!
//! **Use cases**: shared bookmarks, collaborative tagging, membership lists,
//! distributed service registries, IoT device inventories.
//!
//! **Properties**:
//! - Any replica can add items at any time, even while offline
//! - Sync order doesn't matter — replicas converge regardless
//! - No coordination, no leader, no consensus needed
//! - Content-addressing means sync is efficient (skip shared sub-DAGs)

use merkle_crdt::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

struct Sha256Hasher;
impl Hasher for Sha256Hasher {
    type Output = [u8; 32];
    fn hash(data: &[u8]) -> [u8; 32] {
        Sha256::new().chain_update(data).finalize().into()
    }
}

// A G-Set operation is simply "add this item"
#[derive(Clone, Debug)]
struct Add(String);

impl Encode for Add {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.0.encode_to(buf);
    }
}

impl Payload for Add {
    type State = BTreeSet<String>;
    fn apply(state: &mut Self::State, op: &Self) {
        state.insert(op.0.clone());
    }
}

type Replica = MerkleCrdt<Sha256Hasher, Add, MemStore<Sha256Hasher, Add>>;

/// Sync all roots from `src` into `dst`.
fn sync_replicas(dst: &mut Replica, src: &Replica) {
    let roots: Vec<_> = src.roots().iter().cloned().collect();
    for root in roots {
        dst.sync(&root, src.store()).unwrap();
    }
}

fn main() {
    println!("=== Merkle-CRDT: Grow-Only Set ===\n");

    // Three independent replicas (imagine different devices/peers)
    let mut alice: Replica = MerkleCrdt::default();
    let mut bob: Replica = MerkleCrdt::default();
    let mut carol: Replica = MerkleCrdt::default();

    // Each adds items independently — no coordination needed
    alice.apply(Add("rust".into())).unwrap();
    alice.apply(Add("haskell".into())).unwrap();

    bob.apply(Add("python".into())).unwrap();
    bob.apply(Add("rust".into())).unwrap(); // duplicate with Alice — that's fine

    carol.apply(Add("go".into())).unwrap();
    carol.apply(Add("typescript".into())).unwrap();

    println!("Before sync:");
    println!("  Alice:  {:?}", alice.state());
    println!("  Bob:    {:?}", bob.state());
    println!("  Carol:  {:?}", carol.state());

    // Sync in any arbitrary pattern — convergence is guaranteed
    // Alice and Bob sync with each other
    sync_replicas(&mut alice, &bob);
    sync_replicas(&mut bob, &alice);

    // Carol syncs with Alice (who already has Bob's data)
    sync_replicas(&mut carol, &alice);
    sync_replicas(&mut alice, &carol);

    // Bob gets Carol's data through Alice
    sync_replicas(&mut bob, &alice);

    println!("\nAfter sync:");
    println!("  Alice:  {:?}", alice.state());
    println!("  Bob:    {:?}", bob.state());
    println!("  Carol:  {:?}", carol.state());

    assert_eq!(alice.state(), bob.state());
    assert_eq!(bob.state(), carol.state());
    println!("\nAll replicas converged to the same state.");

    // Even syncing again is a no-op (idempotent)
    sync_replicas(&mut alice, &bob);
    assert_eq!(alice.state(), bob.state());
    println!("Re-syncing is idempotent (no wasted work).");

    // Show DAG structure
    println!("\nDAG stats:");
    println!("  Alice: {} roots, {} nodes", alice.roots().len(), alice.store().len());
    println!("  Bob:   {} roots, {} nodes", bob.roots().len(), bob.store().len());
    println!("  Carol: {} roots, {} nodes", carol.roots().len(), carol.store().len());
}
