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
  (`Arrivals`), Liveness and Consensus drained first.

Two implementations:

- `quic::Quic`: QUIC (quinn on smol) with TLS 1.3 bound to node keys both
  ways: each side presents its key as a raw public key (RFC 7250) and
  checks the other's against its configuration. Each node dials the peers
  it sends to and sends only on its own connection; a dropped connection
  is redialed with backoff while frames wait in a bounded queue per peer
  and class. Stateless resets are keyed by the node's secret, so a
  restarted node resets at once the connections its last run held.
- `memory::Hub`: endpoints in one process, for tests, with links that can
  be cut, lose frames at a rate and delay them.

`api` holds the TLS configuration of the node API's QUIC endpoint (its own
protocol, `vos-api/1`, its own allowlist and executor).

## Guarantees

- A frame is delivered at most once, with the authenticated peer it came
  from.
- Order holds within one stream on one connection, and only there: a
  redial can reorder across the old and new connections.
- A send never waits: a queue past its budget refuses, and `ready` says
  when it has room again. A full arrival queue holds its stream's reader,
  and so the sender, as flow control.

## Tests

`cargo test -p vos-net`: unit tests; `tests/memory.rs` (the hub:
partitions, losses, delays, restarts, the peer list); `tests/quic.rs`
(three nodes on localhost: every class, order within a stream, keys not
configured refused on either side, oversized frames, removed and
unreachable peers, quiet streams); `tests/restart.rs` (a peer killed and
started again in a child process); `tests/head_of_line.rs` (consensus
frames' latency beside bulk frames to the same peer).

## Users

On the `vos-core` branch: the node (`node/host`: `src/peer.rs`,
`src/liveness.rs`, `src/dispatch.rs`, `src/api/quic.rs`, `src/tls.rs`),
the HTTP front (`node/http/src/tls.rs`) and the test harness
(`node/checker`).
