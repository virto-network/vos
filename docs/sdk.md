# SDK & Developer Experience

VOS exists so developers can build private applications without
becoming cryptographers. This chapter describes the SDK's design,
API surface, and the abstractions that let application code remain
simple while the protocol handles encryption, anonymity, sync,
credentials, and moderation underneath.

---

## 1. Design Philosophy

### Privacy by default, not by effort

The SDK's primary invariant: **a developer who writes no
privacy-related code gets a fully private application.** Encryption,
anonymous credentials, metadata protection, and key management happen
automatically. The developer writes business logic and CRDT types.
Everything below the application layer is the SDK's responsibility.

This is not convenience — it is a security requirement. Systems where
privacy is opt-in fail in practice. Developers forget, make mistakes,
or ship under deadline pressure. When the default path is private,
every application benefits regardless of the developer's security
expertise.

### One dependency, one import

```rust
use vos::prelude::*;
```

A single crate brings in everything: CRDT types, space management,
sync, encryption, storage, identity, and (when enabled) anonymous
credentials. Feature flags control which layers are compiled in, but
the API surface is unified. There is no separate crate for "VOS
encryption" or "VOS sync" — these are internal layers, not
developer concerns.

### The developer's mental model

The developer thinks in three concepts:

1. **Spaces** — groups of people collaborating on shared state.
2. **Documents** — typed CRDT data structures within a space.
3. **Operations** — mutations to documents that sync automatically.

Everything else — MLS epoch management, DAG node construction,
relay selection, key rotation, anonymous credential proofs, bulletin
board scanning — is invisible to application code unless the
developer explicitly opts into lower-level control.

### Configuration over code

Privacy/performance tradeoffs are expressed as configuration, not
as different code paths. The same application code runs at every
privacy level. Changing from `PrivacyLevel::Fast` to
`PrivacyLevel::Maximum` does not require code changes — only a
config change that affects transport routing, storage strategy, and
credential behavior at the protocol level.

---

## 2. Core API

### Initialization

```rust
use vos::prelude::*;

// Default config: privacy-by-default settings, local storage,
// automatic relay discovery, Tor transport.
let node = Vos::init(Config::default()).await?;

// Custom config for specific requirements.
let node = Vos::init(Config {
    privacy: PrivacyLevel::Maximum,
    storage: StoragePolicy::replicate(vec![
        Backend::Relay("wss://relay.example.com"),
        Backend::Relay("wss://relay2.example.com"),
    ]),
    sync: SyncPolicy::RealTime { batch_interval: Duration::from_millis(200) },
    ..Default::default()
}).await?;
```

`Vos::init` handles: root secret generation (first launch) or
loading (subsequent launches), local store initialization, anonymity
network bootstrap, and relay discovery. The returned `node` is the
entry point for all further operations.

### Space lifecycle

```rust
// Create a space with document templates.
let space = node.create_space(SpaceConfig {
    name: "Project Alpha",
    documents: vec![
        DocTemplate::new::<ChatCrdt>("general"),
        DocTemplate::new::<TextCrdt>("design-doc"),
        DocTemplate::new::<KanbanCrdt>("tasks"),
    ],
    moderation: Moderation::Anonymous {
        reputation_threshold: 10,
        rate_limit: RateLimit::leaky_bucket(100, Duration::from_secs(60)),
    },
    storage: StoragePolicy::replicate(vec![
        Backend::Relay("wss://relay.example.com"),
    ]),
    privacy: PrivacyLevel::Standard,
})?;

// Generate an invite link.
let invite = space.create_invite(InvitePolicy::SingleUse)?;
println!("Share this: {}", invite.to_link());

// Join a space from an invite link.
let space = node.join_space(invite_link).await?;
```

Space creation initializes the MLS group, the root document CRDT,
the membership Merkle tree, and pushes the initial state to the
configured storage backends. All of this is one method call.

### Working with documents

```rust
// Get a typed handle to an existing document.
let chat = space.document::<ChatCrdt>("general")?;

// Apply an operation.
chat.apply(ChatOp::SendMessage {
    text: "Hello, world!".into(),
})?;

// Read current state.
let messages = chat.state().messages();

// Create a new document in the space.
let doc = space.create_document::<CounterCrdt>("vote-count")?;
doc.apply(CounterOp::Increment(1))?;
```

Documents are typed. The generic parameter determines the CRDT
semantics, the operation type, and the state type. The SDK handles
serialization, DAG node construction, MLS encryption, and sync
transparently.

### Sync

```rust
// Explicit sync (useful for manual sync policies).
space.sync().await?;

// Sync is also automatic when using RealTime or Background policies.
// The SDK syncs in the background based on the configured SyncPolicy.
```

In most configurations, sync is automatic. The developer does not
call `sync()` explicitly unless using `SyncPolicy::Manual`. Real-time
sync batches operations at the configured interval (default 100ms)
and pushes them to connected peers and relays.

### Subscribing to changes

```rust
// Callback-based (simple).
space.on_change(|event| {
    match event {
        SpaceEvent::DocumentChanged { doc_id, .. } => {
            println!("Document {} updated", doc_id);
        }
        SpaceEvent::MemberJoined { .. } => { /* ... */ }
        SpaceEvent::MemberLeft { .. } => { /* ... */ }
        SpaceEvent::SyncComplete { .. } => { /* ... */ }
        SpaceEvent::ModerationCallback { .. } => { /* ... */ }
    }
});

// Async stream (for modern Rust patterns).
let mut events = space.events();
while let Some(event) = events.next().await {
    // Process event.
}
```

---

## 3. Custom CRDT Types

### The Payload trait

Every document type implements the `Payload` trait from `merkle-crdt`.
This is the extension point for custom data structures:

```rust
trait Payload {
    /// The operation type applied to this CRDT.
    type Op;
    /// The materialized state type.
    type State;

    /// Serialize an operation to bytes.
    fn encode(op: &Self::Op, buf: &mut Vec<u8>);
    /// Deserialize an operation from bytes.
    fn decode(buf: &[u8]) -> Result<Self::Op>;
    /// Apply an operation to the current state.
    fn apply(op: &Self::Op, state: &mut Self::State);
    /// Return a fresh initial state.
    fn initial() -> Self::State;
}
```

The SDK handles everything else: wrapping operations in DAG nodes,
computing CIDs, encrypting payloads, syncing with peers, and
decrypting + applying incoming operations.

### Example: a counter CRDT

A simple grow-only counter to illustrate the pattern:

```rust
use vos::prelude::*;

/// The CRDT type marker.
struct CounterCrdt;

/// Operations that can be applied.
#[derive(Encode, Decode)]
enum CounterOp {
    Increment(u64),
}

/// The materialized state.
#[derive(Default, Clone)]
struct CounterState {
    value: u64,
}

impl Payload for CounterCrdt {
    type Op = CounterOp;
    type State = CounterState;

    fn encode(op: &CounterOp, buf: &mut Vec<u8>) {
        op.encode_to(buf);
    }

    fn decode(buf: &[u8]) -> Result<CounterOp> {
        CounterOp::decode_from(buf)
    }

    fn apply(op: &CounterOp, state: &mut CounterState) {
        match op {
            CounterOp::Increment(n) => state.value += n,
        }
    }

    fn initial() -> CounterState {
        CounterState::default()
    }
}
```

This counter is grow-only (increments are commutative and
idempotent when deduplicated by CID). For a counter that supports
decrement, a PN-Counter (positive-negative counter with per-peer
tracking) would be needed.

### Example: a task board CRDT

A more complex example showing a practical document type:

```rust
use vos::prelude::*;

struct KanbanCrdt;

#[derive(Encode, Decode)]
enum KanbanOp {
    AddTask { id: TaskId, title: String, column: Column },
    MoveTask { id: TaskId, to_column: Column },
    EditTitle { id: TaskId, title: String },
    RemoveTask { id: TaskId },
}

#[derive(Clone)]
struct KanbanState {
    tasks: HashMap<TaskId, Task>,
}

#[derive(Clone)]
struct Task {
    title: String,
    column: Column,
    removed: bool,  // tombstone for conflict-free removal
}

impl Payload for KanbanCrdt {
    type Op = KanbanOp;
    type State = KanbanState;

    fn apply(op: &KanbanOp, state: &mut KanbanState) {
        match op {
            KanbanOp::AddTask { id, title, column } => {
                state.tasks.entry(*id).or_insert(Task {
                    title: title.clone(),
                    column: *column,
                    removed: false,
                });
            }
            KanbanOp::MoveTask { id, to_column } => {
                if let Some(task) = state.tasks.get_mut(id) {
                    task.column = *to_column; // LWW semantics via causal order
                }
            }
            KanbanOp::EditTitle { id, title } => {
                if let Some(task) = state.tasks.get_mut(id) {
                    task.title = title.clone();
                }
            }
            KanbanOp::RemoveTask { id } => {
                if let Some(task) = state.tasks.get_mut(id) {
                    task.removed = true; // tombstone, not physical delete
                }
            }
        }
    }

    fn initial() -> KanbanState {
        KanbanState { tasks: HashMap::new() }
    }

    // encode/decode omitted for brevity
}
```

The task board uses tombstone-based removal (set a `removed` flag
rather than deleting from the map) to ensure concurrent add and
remove operations converge correctly. Column moves use
last-writer-wins semantics derived from the Merkle-DAG's causal
ordering — if two peers concurrently move the same task to different
columns, the causally later operation wins.

### Future: `#[derive(Crdt)]` macro

A planned procedural macro will generate
`Payload` implementations from annotated struct definitions:

```rust
#[derive(Crdt, Encode)]
struct Marketplace {
    #[crdt(grow_set)]
    listings: GrowSet<Listing>,
    #[crdt(lww)]
    settings: MarketSettings,
}
```

The macro generates the operation enum, serialization, and apply
logic from the field-level CRDT annotations. Until then, manual
`Payload` implementations (as shown above) are required.

---

## 4. Configuration

### PrivacyLevel

Controls the transport and metadata protection layers. The same
application code runs at every level — only the underlying routing
and storage behavior changes.

```rust
enum PrivacyLevel {
    /// Direct WebSocket/WebRTC connections to relays.
    /// Fastest. Relays see real IP addresses.
    /// Suitable for development and low-sensitivity spaces.
    Fast,

    /// All connections routed through Tor (arti).
    /// Relays see Tor exit node IPs, not user IPs.
    /// ~200-500ms added latency. Good default for production.
    Standard,

    /// Tor for real-time sync, Nym mix network for sensitive
    /// operations (credential proofs, key rotations, votes).
    /// Cover traffic enabled. PIR for storage reads.
    /// Uniform envelope sizes enforced.
    /// Highest latency, strongest metadata protection.
    Maximum,
}
```

### StoragePolicy

Determines where encrypted DAG nodes are persisted beyond the local
database:

```rust
enum StoragePolicy {
    /// Local database only. No remote backup.
    /// Data exists only on this device.
    LocalOnly,

    /// Replicate to one or more remote backends.
    /// Encrypted blobs pushed to each backend.
    Replicate(Vec<Backend>),

    /// Erasure-coded distribution: k-of-n fragments
    /// across multiple backends. Any k fragments
    /// reconstruct the data. No single backend holds
    /// enough to reconstruct.
    ErasureCoded {
        k: usize,
        n: usize,
        backends: Vec<Backend>,
    },
}
```

### SyncPolicy

Controls how frequently operations are batched and pushed to peers:

```rust
enum SyncPolicy {
    /// Batch and sync at regular intervals.
    /// Default: 100ms for real-time collaboration.
    RealTime { batch_interval: Duration },

    /// Sync less frequently. Suitable for background
    /// data that does not need instant propagation.
    /// Default: 5 seconds.
    Background { interval: Duration },

    /// No automatic sync. The application calls
    /// space.sync() explicitly.
    Manual,
}
```

### ModerationPolicy

Determines how moderation works within a space:

```rust
enum Moderation {
    /// No moderation. All members can post freely.
    None,

    /// Admin-based moderation. Admins can remove members
    /// from the MLS group (before anonymous mode).
    Admin { admins: Vec<MemberRef> },

    /// Anonymous moderation via zk-promises.

    /// Members post anonymously, moderation enforced
    /// via ZK-proven reputation and rate limits.
    Anonymous {
        reputation_threshold: u64,
        rate_limit: RateLimit,
    },
}
```

---

## 5. Platform Support

### Native Rust

The primary target. Full feature support: Tor transport (via the
`arti` crate), local SQLite/sled storage, native threading, and
direct hardware key access. Suitable for desktop applications
(Linux, macOS, Windows), mobile applications (via platform bindings
to Android NDK or iOS frameworks), and server-side daemons.

### WASM (browsers)

The SDK compiles to WebAssembly via `wasm-bindgen`, enabling
browser-based applications. The WASM build has specific constraints
and adaptations:

| Capability | Native | WASM |
|---|---|---|
| Tor transport | Yes (arti) | No — use relay proxy or WebSocket relay |
| Local storage | SQLite / sled | IndexedDB via wasm-bindgen |
| Threading | OS threads | Web Workers |
| ZK proof generation | Fast (native Arkworks) | Slower (~2-5x overhead) |
| Secure key storage | OS keychain / enclave | SubtleCrypto API (browser sandbox) |
| Mix network (Nym) | Yes | No — use gateway proxy |

**Tor in the browser:** The `arti` crate does not compile to WASM.
Browser applications connect to Nostr relays via standard WebSocket
connections. For IP privacy, the relay should be accessed through a
Tor-friendly proxy, or the application should recommend users run a
Tor browser. This is a known privacy gap in the WASM build — the
documentation and onboarding flow must be transparent about it.

**ZK proofs in the browser:** Arkworks compiles to WASM but proof
generation is slower. For the `ShowAuthorized` proof (~700ms native),
expect ~1.5-3.5 seconds in WASM. This is acceptable for session-start
proofs but reinforces the need for session tokens rather than
per-operation proofs. Newer proof systems (Jolt, SP1) that target
WASM efficiency are being evaluated for future phases.

### `no_std` core

The `merkle-crdt` crate (sync layer) is `no_std` by default. The
core data structures — `MerkleClock`, `MerkleCrdt`, `Store`,
`Payload`, `Hasher`, `Encode` traits — compile without the standard
library. This enables:

- **Embedded devices and IoT:** Sensor networks, smart home devices,
  or edge nodes that participate in spaces with constrained hardware.
- **Bare-metal targets:** Custom firmware that needs CRDT sync without
  a full OS.

The `no_std` core handles DAG construction and CRDT application. The
higher layers (MLS encryption, ZK proofs, network transport) require
`std` or platform-specific implementations. A `no_std` device would
typically sync DAG nodes via a serial connection or BLE to a more
capable peer that handles encryption and network access.

---

## 6. Event System

### Event types

The SDK surfaces protocol events to the application through a
unified event system. Every significant state change produces an
event:

```rust
enum SpaceEvent {
    /// A document's CRDT state changed (local edit or remote sync).
    DocumentChanged {
        doc_id: DocumentId,
        source: ChangeSource, // Local or Remote
    },

    /// A new member joined the space (MLS Welcome processed).
    MemberJoined {
        epoch: u64,
    },

    /// A member left or was removed (MLS Commit processed).
    MemberLeft {
        epoch: u64,
    },

    /// A sync cycle completed with a peer or relay.
    SyncComplete {
        peer: PeerId,
        nodes_received: usize,
        nodes_sent: usize,
    },

    /// A moderation callback was received (zk-promises).
    /// The application may want to notify the user.
    ModerationCallback {
        callback_type: CallbackType,
    },

    /// MLS epoch advanced (key rotation occurred).
    EpochAdvanced {
        new_epoch: u64,
    },
}
```

### Delivery modes

**Callback-based:** Register a closure that is called for every event.
Simple, works well for UI frameworks with their own event loops.

```rust
space.on_change(|event| { /* handle event */ });
```

**Async stream:** Returns an `impl Stream<Item = SpaceEvent>` for
use with `async`/`await` patterns. Integrates with tokio, smol, or
WASM futures.

```rust
let mut events = space.events();
while let Some(event) = events.next().await {
    match event { /* ... */ }
}
```

**Filtered streams:** Subscribe to specific event types to avoid
processing irrelevant events in performance-sensitive UI code:

```rust
let mut doc_changes = space.events()
    .filter(|e| matches!(e, SpaceEvent::DocumentChanged { .. }));
```

### UI framework integration

The event system is designed to work with reactive UI frameworks.
Events are delivered on a configurable executor — applications using
a UI thread can route events to that thread. The SDK does not depend
on any specific UI framework, but the event system's design (typed
events, filter support, async streams) maps naturally to patterns
used by egui, Dioxus, Leptos, Yew, and similar Rust UI libraries.

---

## 7. Error Handling & Debugging

### Typed errors

Each SDK layer has its own error type. Errors compose through a
top-level `VosError` enum:

```rust
enum VosError {
    /// Space lifecycle errors (create, join, leave).
    Space(SpaceError),
    /// Document errors (CRDT apply, serialization).
    Document(DocumentError),
    /// Sync errors (network, relay, DAG walking).
    Sync(SyncError),
    /// Encryption errors (MLS, key derivation, decryption failure).
    Encryption(EncryptionError),
    /// Storage errors (local DB, relay, erasure coding).
    Storage(StorageError),
    /// Credential errors (ZK proof generation, verification).
    Credential(CredentialError),
    /// Transport errors (Tor, mix network, WebSocket).
    Transport(TransportError),
}
```

Each variant carries structured context (which space, which
document, which epoch) to aid diagnosis without exposing sensitive
data.

### Privacy-safe logging

The SDK's logging system enforces a strict rule: **logs never
contain plaintext content, cryptographic keys, or CIDs that could
identify a specific space or document to an observer.** This applies
at all log levels, including `TRACE`.

What is logged:

- Operation counts ("synced 14 nodes")
- Timing ("sync completed in 230ms")
- Error categories ("MLS decryption failed: unknown epoch")
- Protocol state transitions ("epoch advanced: 7 -> 8")

What is never logged:

- Plaintext CRDT operation content
- Encryption keys, epoch secrets, root secrets
- Raw CIDs (which could correlate logs to specific spaces if an
  adversary obtains both the logs and the relay's event store)
- Member identifiers or credential commitments
- Invite tokens or space parameters

CIDs are logged only in truncated, salted form:
`log_cid = truncate(HMAC(session_salt, cid), 8 bytes)`. This
allows correlating log entries within a single session for debugging
but prevents matching log entries to stored DAG nodes.

### Debug mode

An opt-in debug mode (`Config::debug(true)`) relaxes the logging
restrictions for development:

```rust
let node = Vos::init(Config {
    debug: true,  // DEVELOPMENT ONLY — logs sensitive data
    ..Default::default()
}).await?;
```

In debug mode, full CIDs, operation details, and protocol messages
are logged. A compile-time `#[cfg(debug_assertions)]` gate prevents
debug mode from being enabled in release builds. The SDK prints a
prominent warning at startup if debug mode is active:

```
⚠ VOS debug mode is ON. Sensitive data will appear in logs.
  Do not use this in production.
```

### Diagnostic tools

The SDK provides introspection methods for development and
troubleshooting:

```rust
// Inspect the DAG state of a document.
let dag_info = doc.dag_info()?;
println!("Roots: {}", dag_info.root_count);
println!("Total nodes: {}", dag_info.node_count);
println!("Depth: {}", dag_info.max_depth);

// Check MLS group state.
let group_info = space.group_info()?;
println!("Current epoch: {}", group_info.epoch);
println!("Member count: {}", group_info.member_count);

// Check sync status with a specific peer or relay.
let sync_status = space.sync_status(relay)?;
println!("Last sync: {:?}", sync_status.last_sync);
println!("Pending nodes: {}", sync_status.pending_outbound);
```

These methods return aggregate information (counts, timestamps,
status flags) rather than raw protocol data, maintaining the
privacy-safe logging principle even in diagnostic contexts.
