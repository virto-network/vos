//! # Decentralized Chat — Operation-Based Merkle-CRDT
//!
//! Demonstrates a peer-to-peer chat system where messages are operation-based
//! CRDT operations stored in a Merkle-DAG. The DAG provides causal ordering,
//! so messages always appear in a consistent order across replicas.
//!
//! **Use cases**: P2P chat, collaborative event logs, audit trails,
//! distributed task queues, IoT sensor event streams.
//!
//! **Properties**:
//! - Messages are ordered by causality (replies always come after what they reply to)
//! - Concurrent messages get a deterministic total order (sorted by CID)
//! - Works over any transport (DHT, PubSub, USB stick)
//! - Replicas can go offline and resync later without losing messages

use merkle_crdt::*;
use sha2::{Digest, Sha256};

struct Sha256Hasher;
impl Hasher for Sha256Hasher {
    type Output = [u8; 32];
    fn hash(data: &[u8]) -> [u8; 32] {
        Sha256::new().chain_update(data).finalize().into()
    }
}

// A chat message: who said what
#[derive(Clone, Debug)]
struct Message {
    author: String,
    text: String,
}

impl Encode for Message {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.author.encode_to(buf);
        self.text.encode_to(buf);
    }
}

// The chat log: an ordered list of messages
impl Payload for Message {
    type State = Vec<Message>;
    fn apply(state: &mut Self::State, op: &Self) {
        state.push(op.clone());
    }
}

type ChatReplica = MerkleCrdt<Sha256Hasher, Message, MemStore<Sha256Hasher, Message>>;

fn say(replica: &mut ChatReplica, author: &str, text: &str) -> Cid<Sha256Hasher> {
    let msg = Message {
        author: author.into(),
        text: text.into(),
    };
    replica.apply(msg).unwrap()
}

fn sync(dst: &mut ChatReplica, src: &ChatReplica) {
    let roots: Vec<_> = src.roots().iter().cloned().collect();
    for root in roots {
        dst.sync(&root, src.store()).unwrap();
    }
}

fn print_log(name: &str, replica: &ChatReplica) {
    println!("  {name}'s log:");
    if replica.state().is_empty() {
        println!("    (empty)");
    }
    for msg in replica.state() {
        println!("    <{}> {}", msg.author, msg.text);
    }
}

fn main() {
    println!("=== Merkle-CRDT: Decentralized Chat ===\n");

    let mut alice: ChatReplica = MerkleCrdt::default();
    let mut bob: ChatReplica = MerkleCrdt::default();

    // Alice and Bob chat independently (imagine they're offline from each other)
    say(&mut alice, "Alice", "Hey! Anyone here?");
    say(&mut alice, "Alice", "I'm working on the Merkle-CRDT paper");

    say(&mut bob, "Bob", "Just joined the channel");
    say(&mut bob, "Bob", "Has anyone seen the new CRDT library?");

    println!("Before sync (each peer only sees their own messages):");
    print_log("Alice", &alice);
    print_log("Bob", &bob);

    // They reconnect and sync
    println!("\n--- Syncing ---\n");
    sync(&mut alice, &bob);
    sync(&mut bob, &alice);

    println!("After sync (both see all messages):");
    print_log("Alice", &alice);
    print_log("Bob", &bob);

    // Continued conversation — Alice sees Bob's messages and replies
    say(&mut alice, "Alice", "Bob! Yes, check out merkle-crdt");
    say(&mut bob, "Bob", "Oh cool, Alice is here!");

    // Sync again
    sync(&mut alice, &bob);
    sync(&mut bob, &alice);

    println!("\nAfter more chatting and syncing:");
    print_log("Alice", &alice);
    print_log("Bob", &bob);

    println!("\nMessages: {}", alice.state().len());
    println!("DAG nodes: {}", alice.store().len());
    println!("Roots: {} (concurrent heads)", alice.roots().len());

    // Demonstrate that a third peer can join and cold-sync the entire history
    println!("\n--- Carol joins and syncs everything from Alice ---\n");
    let mut carol: ChatReplica = MerkleCrdt::default();
    sync(&mut carol, &alice);
    print_log("Carol", &carol);
    assert_eq!(carol.state().len(), alice.state().len());
    println!("\nCarol has the complete history without ever being online during the conversation.");
}
