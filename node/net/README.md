# vos-net

A network of nodes that know each other by their ed25519 keys:
authenticated channels between node keys, classes of traffic the caller
defines, and streams by id or by frame. Frames are bytes, and their
meaning belongs to the layer above.

## The model

- **A peer is its ed25519 key and its address.** Every arrival carries the
  authenticated key it came from, and a node takes frames only from the
  keys it lists. Naming peers otherwise (by a number, a role) is the
  caller's, over the keys.
- **Classes of traffic** are a table the caller supplies (`Classes`, at
  most `MAX_CLASSES`); a class is its index in it, and the byte that opens
  each stream. Each class (`ClassSpec`) has a priority (a stream of a
  higher one is sent first), a bound on a frame's size, a bound on its
  arrival queue in frames, its streams (`Streams::PerId` or
  `Streams::PerFrame`), and an optional age past which a frame waiting to
  be sent is dropped, for frames that say something only while fresh.
- **Streams.** A class of streams per id sends on a long-lived stream per
  id, which the caller chooses, so one id's large frame never delays
  another's; a class of streams per frame opens a stream per frame.
- **The interface** is the `Network` trait: `send` refuses with a reason
  (`Refused`: a full queue, an unknown peer or class, an oversized frame, a
  link down for good), and arrivals come in a bounded queue per class
  (`Arrivals`), which the consumer drains in an order of its own.

Two implementations:

- `quic::Quic`: QUIC (quinn on smol) with TLS 1.3 bound to node keys both
  ways: each side presents its key as a raw public key (RFC 7250) and
  checks the other's against its configuration. Each node dials the peers
  it sends to and sends only on its own connection; the dialed side may
  open no stream on it. A dropped connection is redialed on the next frame
  sent, with backoff when it was refused or closed soon after it was made;
  frames sent meanwhile wait in a bounded queue per peer and class, and
  those already handed to the dropped connection are lost with it. The
  caller names the protocol (`quic::Protocol`): its ALPN name, and the
  domain the endpoint's keys are derived under. Stateless resets are
  keyed by the node's secret, the domain and the ALPN name, so a restarted
  node resets at once the connections its last run held, and an endpoint
  of one protocol gives out no reset token of another's connections.
- `memory::Hub`: endpoints in one process, for tests, with links that can
  be cut, lose frames at a rate and delay them. It drops no frame for its
  age.

For a QUIC endpoint of the caller's own (a client-server protocol over the
same keys), `quic::server_config`, `quic::client_config` and
`quic::endpoint_config` build its TLS and endpoint configurations (an
allowlist of keys on the accepting side, one pinned key on the dialing
side), and `quic::Runner` gives it an executor of its own; address
validation and bounds on its handshakes and connections are its caller's.

## Guarantees

- A frame is delivered at most once, with the authenticated peer it came
  from.
- Order holds within one id on one connection, and only there: a redial
  can reorder across the old and new connections.
- A send never waits: a queue past its budget refuses, and `ready` says
  when it has room again. A full arrival queue holds its stream's reader,
  and so the sender, as flow control.
- No age bound but a class's own: a frame of a class without an age,
  queued through an outage, is sent when the peer is reached again,
  however late.

## Bounds against peers

What a sender can make a node spend, over QUIC:

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
  A peer removed from the table loses it at once.
- **Frames being assembled:** each class's frames from one peer take
  their bytes from a budget of 4 of that class's largest frames (1 MiB
  at least; a budget under its bound takes one frame more) before they
  are read; past it a stream waits unread.
- **Frames waiting for the consumer:** each class's queue holds, from
  every peer, the bytes of 4 of its largest frames, counted the same
  way (and the class's own bound in frames); a frame counts until the
  consumer drops it.
- These budgets are per class, so what a peer can make a node hold
  grows with the number of classes in the table (at least 1 MiB each).
- **Protocol violations:** the first is logged; at the 16th on one
  connection, it is closed.

Limits that stay:

- What quinn buffers for a peer's streams not being read is bounded by
  `quic::Config::streams` times a stream's window (1 MiB): 8 GiB at the
  default of 8,192 streams. A finite connection window would bound it
  lower but would let unread streams of one class stall a peer's other
  classes; a node sets `streams` to what its traffic needs.
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

`cargo test -p vos-net`, with a table of four classes like a cluster's
(heartbeats with an age, two classes of streams per id, and large frames
a stream each): unit tests; `tests/memory.rs` (the hub: partitions,
losses, delays, restarts, the peer list); `tests/quic.rs` (three nodes on
localhost: every class, order within a stream, keys not configured
refused on either side, a frame past its class's age, oversized frames,
removed and unreachable peers, each class's send queue budget, quiet
streams); `tests/restart.rs` (a peer killed and started again in a child
process); `tests/head_of_line.rs` (small frames' latency beside large
frames to the same peer); `tests/hostile.rs` (the bounds above, against
peers and strangers running code of their own).
