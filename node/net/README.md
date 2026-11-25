# vos-net

The network between VOS nodes: authenticated channels between node keys,
classes of traffic, and streams by id or by frame. It knows nothing of
consensus; frames are bytes, and their meaning belongs to the layer above.

## The model

- **A node is its ed25519 key.** Every arrival carries the authenticated
  peer it came from, and a node takes frames only from the peers it lists.
- **Classes of traffic** (`Class`): Liveness (pair heartbeats), Consensus,
  Requests and Bulk, each with its priority, its own arrival queue and its
  own bound on a frame's size (`Limits`).
- **Streams.** Liveness, Consensus and Requests frames travel on a
  long-lived stream per id, which the caller chooses, so one id's large
  frame never delays another's; Bulk opens a stream per frame.
- **The interface** is the `Network` trait: `send` refuses with a reason
  (`Refused`: a full queue, an unknown peer, an oversized frame, a link
  down for good), and arrivals come in a bounded queue per class
  (`Arrivals`), which a consumer drains Liveness and Consensus first.

Two implementations:

- `quic::Quic`: QUIC (quinn on smol) with TLS 1.3 bound to node keys both
  ways: each side presents its key as a raw public key (RFC 7250) and
  checks the other's against its configuration. Each node dials the peers
  it sends to and sends only on its own connection; the dialed side may
  open no stream on it. A dropped connection is redialed on the next frame
  sent, with backoff when it was refused or closed soon after it was made;
  frames sent meanwhile wait in a bounded queue per peer and class, and
  those already handed to the dropped connection are lost with it.
  Stateless resets are keyed by the node's secret and the endpoint's
  protocol, so a restarted node resets at once the connections its last
  run held, and the node API's endpoint gives out no reset token of a
  peer connection.
- `memory::Hub`: endpoints in one process, for tests, with links that can
  be cut, lose frames at a rate and delay them.

`api` holds the TLS configuration of the node API's QUIC endpoint (its own
protocol, `vos-api/1`, its own allowlist, keys and executor); address
validation and bounds on its handshakes and connections are its caller's.

## Guarantees

- A frame is delivered at most once, with the authenticated peer it came
  from.
- Order holds within one id on one connection, and only there: a redial
  can reorder across the old and new connections.
- A send never waits: a queue past its budget refuses, and `ready` says
  when it has room again. A full arrival queue holds its stream's reader,
  and so the sender, as flow control.
- No age bound but Liveness's: a frame queued through an outage is sent
  when the peer is reached again, however late.

## Bounds against peers

What a sender can make a node spend, over QUIC (`quic::Config`):

- **Handshakes.** A sender proves its address (a QUIC retry) before the
  node runs its side of a handshake. Handshakes under way are bounded per
  address (8, times the configured peers at that address; an IPv6
  address counts by its /64) and, for addresses no configured peer has,
  64 in all. A handshake has 10 s; one that fails keeps its place for 1 s,
  so a stranger's address costs the node at most 8 handshakes a second,
  and every stranger together 64, on the thread that carries the peers'
  frames. Strangers at other addresses never take a peer's own
  address's places; a peer that dials from an address other than its
  configured one competes with strangers for the 64.
- **One inbound connection per key:** a newer one replaces the older.
  A peer removed from the table, or given another number, loses it at
  once.
- **Frames being assembled:** each class's frames from one peer take
  their bytes from a budget of 4 of that class's largest frames (1 MiB
  at least; a budget under its bound takes one frame more) before they
  are read; past it a stream waits unread.
- **Frames waiting for the consumer:** each class's queue holds, from
  every peer, the bytes of 4 of its largest frames, counted the same
  way (and 1,024 frames, 16 for Bulk); a frame counts until the consumer
  drops it.
- **Protocol violations:** the first is logged; at the 16th on one
  connection, it is closed.

Limits that stay:

- What quinn buffers for a peer's streams not being read is bounded by
  `quic::Config::streams` times a stream's window (1 MiB): 8 GiB at the
  default of 8,192 streams, 4 GiB at the 4,096 a VOS node sets. A finite connection window would bound it
  lower but would let unread streams of one class stall a peer's
  heartbeats; a node sets `streams` to what its traffic needs.
- A peer's frames of one class share that class's queue with every other
  peer's, so a peer that floods takes most of its places.
- A configured peer can still spend the node's thread on what it sends;
  vos-net bounds memory and handshakes, not a peer's well-formed traffic.
- A frame queued before its peer was removed may still be read after.
- Every sender's first datagram still costs the node a retry, and one
  past its address's places a refusal, on the network's thread.
- A stranger sharing a peer's address (behind one NAT, in one IPv6 /64)
  shares that address's places.
- Peers' connections do not migrate: a peer whose NAT binding changes
  loses its inbound connection until it idles out, and redials.

## Tests

`cargo test -p vos-net`: unit tests; `tests/memory.rs` (the hub:
partitions, losses, delays, restarts, the peer list); `tests/quic.rs`
(three nodes on localhost: every class, order within a stream, keys not
configured refused on either side, oversized frames, removed and
unreachable peers, quiet streams); `tests/restart.rs` (a peer killed and
started again in a child process); `tests/head_of_line.rs` (consensus
frames' latency beside bulk frames to the same peer); `tests/hostile.rs`
(the bounds above, against peers and strangers running code of their
own).

## Users

Built for the VOS node (`node/host`: `src/peer.rs`,
`src/liveness.rs`, `src/dispatch.rs`, `src/api/quic.rs`, `src/tls.rs`,
`src/client/api.rs`), the HTTP front (`node/http/src/tls.rs`), the
gateway (`node/gateway/src/upstream.rs`), the scale harness
(`tools/scale`) and the carrier audit's capture of the hub's frames
(`node/checker/src/carriers/capture.rs`).
