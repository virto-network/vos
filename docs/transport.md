# Transport Layer: Anonymity Networks

Encrypting content is not enough. If an adversary can see *who* talks to
*whom*, *when*, and *how often*, they learn the social graph and activity
patterns even without reading a single message. The transport layer exists
to hide these metadata signals.

Kunekt is transport-agnostic. The protocol only needs to move encrypted
DAG nodes between peers and storage backends. Any channel that can carry
bytes works. The interesting question is not *how* to deliver bytes, but
how to do it without leaking who is delivering them.

## Transport agnosticism

The sync and storage layers operate on a simple contract:

```rust
trait Transport {
    /// Send an encrypted blob to a destination.
    fn send(&self, destination: Address, blob: &[u8]) -> Result<()>;

    /// Receive the next incoming blob and the source it arrived from.
    fn receive(&self) -> Result<(Address, Vec<u8>)>;
}
```

`Address` is opaque to upper layers — it could be a Nostr relay URL, a
Tor hidden service, a Nym gateway address, or a Bluetooth device ID. The
protocol does not care. It hands encrypted bytes down and gets encrypted
bytes back.

Implementations can be stacked. A single message might travel through
Nym to a gateway, then over a WebSocket to a Nostr relay. Each layer
wraps the previous one:

```
Nym → WebSocket → Relay
```

This composability means new transports can be added without touching the
protocol core.

## Direct connections

The simplest transports connect peers without any anonymity routing.

- **WebSocket** — the standard Nostr relay transport. A peer opens a
  persistent connection to a relay and exchanges NIP-01 events. Works
  everywhere, including browsers.
- **WebRTC** — browser-to-browser direct connections using DTLS. Useful
  for real-time collaboration when both peers are online simultaneously.
- **libp2p** — peer-to-peer networking with built-in NAT traversal,
  multiplexing, and peer discovery. Suited for native desktop and server
  peers.
- **Bluetooth / USB / NFC** — local-range transports for device-to-device
  sync. An air-gapped device can sync its DAG over Bluetooth without
  ever touching the internet.

Direct connections are fast but have a privacy cost: they reveal IP
addresses and, if two peers connect directly, confirm that those peers
are communicating. An observer watching the network sees the full peer
graph in plaintext.

## Onion routing (Tor)

Tor hides the origin of a connection by routing it through a circuit of
three relays. Each relay peels one layer of encryption and forwards the
message to the next hop. No single relay knows both the sender and the
destination.

```
Peer → Guard → Middle → Exit → Destination
         ↓        ↓        ↓
      knows     knows    knows
      sender    neither  destination
```

**Latency.** A Tor circuit adds roughly 200--500ms of round-trip latency.
This is acceptable for batched CRDT operations — a collaborative document
that syncs every few hundred milliseconds feels responsive enough for
most workflows.

**Hidden services.** When both peers run Tor hidden services (`.onion`
addresses), traffic never leaves the Tor network. There is no exit node,
which removes the exit-node attack surface entirely. Peer-to-peer sync
over hidden services is the recommended default for Kunekt.

**Rust integration.** The [arti](https://gitlab.torproject.org/tpo/core/arti)
crate provides a pure-Rust, embeddable Tor implementation. Kunekt peers
can run an arti client in-process rather than depending on a system Tor
daemon.

**Limitations.** Tor is vulnerable to traffic correlation: an adversary
who observes both the entry guard and the destination can match flows by
timing and volume. It does not reorder or delay messages, so traffic
patterns are preserved end to end.

## Mix networks (Nym)

A mix network provides stronger anonymity than onion routing by breaking
the timing link between sender and receiver.

Messages enter through a gateway, pass through three layers of mix nodes,
and exit through another gateway. At each layer, the mix node:

1. Decrypts one layer of encryption (like Tor)
2. **Batches** incoming messages and holds them for a random delay
3. **Reorders** the batch before forwarding

```
Peer → Gateway → Mix₁ → Mix₂ → Mix₃ → Gateway → Destination
                  │       │       │
               batch   batch   batch
               delay   delay   delay
               reorder reorder reorder
```

The batching and reordering destroy the timing correlation that Tor
leaves intact. An adversary watching every node in the network still
cannot link a specific input message to a specific output message
without breaking the cryptographic sphinx packet format.

**Latency.** The mixing adds 1--5 seconds of end-to-end delay. This is
too high for real-time keystroke-level editing, but well within tolerance
for operations that don't need instant feedback:

- Credential proofs
- MLS key rotations and Commits
- Governance votes
- Storage operations (push/fetch encrypted blobs)

**Cover traffic.** Nym generates loop cover traffic automatically: each
client sends a steady stream of encrypted dummy messages that are
indistinguishable from real traffic. This prevents an observer from
inferring activity patterns by watching message rates.

**Rust integration.** The
[Nym Rust SDK](https://github.com/nymtech/nym) provides client
libraries for connecting to the mixnet, sending sphinx packets, and
receiving replies through Single-Use Reply Blocks (SURBs).

## Tiered transport strategy

Not every operation needs the same level of anonymity. A real-time CRDT
keystroke does not warrant 3 seconds of mix-network delay, but a
credential proof that reveals group membership absolutely does.

Kunekt uses a tiered strategy — different operation types route through
different transports:

```
Operation Type          Transport          Latency    Anonymity
────────────────────────────────────────────────────────────────
Real-time CRDT ops      Tor                ~300ms     Good
MLS key rotations       Nym mix net        ~2s        Strong
Credential proofs       Nym mix net        ~3s        Strong
Relay storage ops       Tor                ~400ms     Good
High-risk governance    Nym mix net        ~3s        Strong
Local device sync       Direct/Bluetooth   <10ms      N/A
Low-sensitivity public  Direct WebSocket   <50ms      None
```

The tier is configurable per space through a privacy level setting:

| Privacy Level | Behavior |
|---|---|
| `Fast` | All traffic over direct connections. No anonymity routing. |
| `Standard` | CRDT ops over Tor, sensitive ops over Nym. Default. |
| `Maximum` | All traffic over Nym. Highest latency, strongest anonymity. |

Individual operations can override the space default. A space running at
`Standard` level can still route a single high-stakes governance vote
through Nym by tagging it as sensitive.

## Cover traffic

Even with anonymity routing, traffic *volume* is a signal. If a peer
sends a burst of messages every time a user edits a document, an
observer on the local network can infer activity patterns without
knowing the content or destination.

Cover traffic defeats this by maintaining a constant message rate
regardless of actual activity.

**Over Nym.** The mixnet provides cover traffic natively. Each Nym client
sends a configurable stream of loop messages that are cryptographically
indistinguishable from real traffic. No application-level work needed.

**Over Tor.** Tor does not provide cover traffic, so Kunekt generates it
at the application level. The peer sends encrypted no-op DAG nodes (nodes
with an empty payload and no causal dependencies) at fixed intervals.
These no-ops are valid DAG nodes that relays store and other peers
discard on decryption.

**Configuration.** Cover traffic rate is a bandwidth-vs-privacy tradeoff.
A higher rate makes traffic analysis harder but costs more bandwidth.
Defaults are tuned per privacy level:

- `Fast` — no cover traffic
- `Standard` — 1 cover message per 10 seconds over Tor
- `Maximum` — Nym native cover traffic (continuous)

## Relay hopping and multi-path

Connecting to the same relay for every operation gives that relay a
complete view of a peer's access patterns — which CIDs are fetched,
when, and how often. Even though the relay cannot decrypt the content,
the access pattern itself is metadata.

Kunekt mitigates this with relay diversity:

- **Rotate relay connections.** Don't maintain a persistent connection to
  a single relay. Periodically disconnect and reconnect to a different
  relay from the space's relay set.
- **Spread operations.** Write DAG nodes to multiple relays. Fetch
  different subsets of the DAG from different relays. No single relay
  sees the full picture.
- **Multi-path fetch.** When syncing a document, request different DAG
  nodes from different relays in parallel. This improves both privacy
  (no relay sees the full access pattern) and performance (parallel
  fetches reduce sync time).

Combined with Tor or Nym routing, relay hopping means each relay sees
traffic from a different circuit or mix route, making it difficult to
link requests to the same peer.

## NAT traversal and connectivity

Most peers are behind NATs and cannot accept incoming connections
directly. Kunekt handles this at multiple levels:

- **Relay-mediated.** The default path. Peers connect outward to Nostr
  relays and exchange messages through them. Since relays are public
  servers, NAT is not an issue. This always works.
- **WebRTC ICE.** For browser-to-browser connections, WebRTC's ICE
  protocol handles STUN/TURN negotiation to punch through NATs when
  possible, falling back to a TURN relay when not.
- **libp2p hole-punching.** For native apps, libp2p's AutoNAT and relay
  protocols detect NAT type and attempt direct connections through
  UDP hole-punching, using a relay as coordinator.
- **Fallback guarantee.** Relay-mediated communication is always
  available. Direct connections are an optimization, never a
  requirement. A peer behind the strictest NAT can still participate
  fully through relays.

## Transport security properties

The following table summarizes the privacy properties of each transport
option:

| Transport | IP Hidden | Timing Hidden | Traffic Analysis Resistant | Latency |
|---|---|---|---|---|
| Direct | No | No | No | <50ms |
| Tor | Yes | Partially | Partially | 200--500ms |
| Nym | Yes | Yes | Yes | 1--5s |
| Tor + cover traffic | Yes | Mostly | Mostly | 200--500ms |

**IP Hidden** — whether an observer can link traffic to the peer's IP
address.

**Timing Hidden** — whether message timing is preserved end to end. Tor
preserves timing (an observer can correlate entry and exit flows). Nym
breaks timing through mixing delays.

**Traffic Analysis Resistant** — whether an observer watching the full
network can determine communication patterns. Only mix networks with
cover traffic provide strong resistance.

The tiered strategy lets each space and each operation choose where to
sit on this tradeoff curve. Most users will run at `Standard` level,
getting Tor's low latency for interactive operations and Nym's strong
anonymity for sensitive ones.
