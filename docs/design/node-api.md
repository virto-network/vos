# The node API and the gateway

The brief of slice 7's step 7.10b (`slice-7-mobile.md`), written before
any code so Fable reads the frame grammar and the kind table first, then
revised with that review (`research/slice-7/7.10b-brief-fable.md`, M1–M8
and L1–L15) and the answers to its questions (§10). The node keeps one
binary API; its HTTP, public TLS and front-end concerns move to a gateway
that holds no authority [decided, S41]. It builds on
`identity-and-authority.md` §5–§6 (the credentialed call, operator
requests) and the owner's S40, S41, S46, S49 and S50
(`research/slice-7/owner-decisions.md`).

Tags as in the plan: [decided] the owner's; [proposed] open to review;
[measured] by a run. Everything not tagged is [proposed]; the answers of
§10 are the orchestrator's calls unless marked the owner's.

## 1. What exists

- **The ingress** (`node/host/src/ingress.rs`) serves HTTP/1.1
  (`http.rs`, `Content-Length` bodies only, keep-alive, 16 KiB heads,
  30 s idle, 60 s a request) in plain HTTP on loopback or TLS 1.3
  (`tls.rs`: a certificate for the node's key, which clients pin, or PEM
  files). Every body is at most `cap::REQUEST` plus a 4 KiB envelope
  (69,632 bytes), an install's `MAX_ELF` plus 4 KiB (67,112,960). Its
  fourteen routes are the kind table's (§3). Operator routes take a
  bearer token the node writes to `admin.token` in its data directory.
- **The client** (`node/host/src/client/`) is blocking: `http.rs` keeps
  connections; `Client` signs calls, queries and workflow reads, follows
  `NotLeader` and `Elsewhere` (4 redirects, 6 failovers); `Operator`
  carries the token. `vos`, the checker, the host's tests and
  `vos-scale` use it; `vos-scale`'s drivers keep their own async pool of
  HTTP connections (`tools/scale/src/engine/pool.rs`), signing with
  `signed_call` and `signed_query`.
- **The peer network** (`node/net`) is QUIC (quinn, `runtime-smol`) with
  TLS 1.3 and raw ed25519 public keys (RFC 7250) on both sides, ALPN
  `vos/1`, the accepting side checking the dialer against the configured
  peers, no session resumption; unidirectional streams only, framed by a
  big-endian `u32` length, on a network thread of its own.
- **The encoding.** The plan says SCALE. `vos_wire` encodes with
  `vos-pvm-codec`, "SCALE without compact encoding": integers fixed-width
  little-endian; `Vec<T>` and `String` a `u32` little-endian count, then
  the items; `[T; N]` no prefix; `Option` a byte 0 or 1, then the value;
  an enum a `u8` index (`#[codec(index = n)]`), then the variant's
  fields; `decode_exact` refuses trailing bytes. It is not
  parity-scale-codec's encoding of any type holding a vector. This doc's
  "SCALE" is this codec.
- **s4's server** (`~/src/virto/s4/server`) is tokio and russh 0.61. It
  dispatches SSH subsystems by a fixed match (`s4-ui`, `s4-flow`,
  `server.rs`); any other name is refused. Authentication is pluggable
  (`authenticator_fn`), and its `Identity` is the key's fingerprint.

## 2. The frame grammar

- **A frame** [decided shape, S41; widths proposed in the plan and
  confirmed here]:

  | field | bytes | |
  |---|---|---|
  | `length` | 4, `u32` LE | the bytes that follow it |
  | `kind` | 2, `u16` LE | §3's number; `0xffff` the frame error |
  | `id` | 8, `u64` LE | **on a byte stream only** (the socket, the `vos-api` channel) |
  | body | `length − 2` (QUIC) or `length − 10` (stream) | the kind's request or answer, in SCALE |

  The header is 6 bytes over QUIC and 14 over a byte stream. Little-endian
  throughout, as the codec, where `vos-net`'s peer frames carry a
  big-endian length: the two never meet (separate ports and ALPNs, §5). A
  `u32` length bounds a frame at 4 GiB, past every limit (the largest, an
  install, is 64 MiB plus 4 KiB plus 160).
- **An answer frame** carries the request's `kind`, or `0xffff` for a
  frame error, and (on a stream) the request's `id`, then the answer's
  body. A request has exactly one answer frame, or none if the connection
  ends first.
- **Ids** are the client's: the node echoes them and keeps no table, so
  an id reused while in flight gives the client two answers it cannot
  tell apart. Clients count from 1. A frame error the node cannot tie to a
  request (a length too short to hold an id) carries id 0. A relay keeps
  the only table: its own upstream ids, mapped back to the client's.
- **Read before decoding,** in this order, each failure a frame error:
  1. `length` below the header's rest (2, or 10): `Truncated`;
  2. `kind` not in the table: `UnknownKind`, `0xffff` among them (a frame
     error is an answer, never a request);
  3. on a relay, `kind` not relayable there: `NotRelayed` (§6);
  4. the body (`length` less the header's rest) past the kind's limit:
     `Oversize { limit }`, before any body byte is read or allocated;
  5. the stream or connection ending before `length` bytes:
     `Truncated` (answered if the peer still reads, else nothing).

  Then the body is decoded exactly (`decode_exact`). A body that does not
  decode is not a frame error: it is the kind's own answer, for kinds
  answering `Response` a `Rejected(Malformed)` (HTTP 400), as today; for
  `AgentInfo` and `Schema` (answering `Option`s) `None`, as HTTP's empty
  404 for an id that is not a `u32` is today.
- **The frame error,** kind `0xffff`, its body a `FrameError`:

  ```rust
  #[derive(Encode, Decode)]
  pub enum FrameError {
      #[codec(index = 0)]
      Oversize { limit: u32 },   // the kind's body limit
      #[codec(index = 1)]
      UnknownKind,
      #[codec(index = 2)]
      Truncated,
      #[codec(index = 3)]
      NotRelayed,                // a relay's only (§6); a node never sends it
      #[codec(index = 4)]
      Unavailable,               // a relay's only: no node answered (§6)
  }
  ```
  `Unavailable` is added to the plan's four [orchestrator, Q-D]: a relay
  whose upstream fails mid-request must answer every kind, and three
  kinds answer types with no `Unavailable` of their own (`NodeKey`,
  `Time`, the `Option`s). A node answers the `Response` kinds' own
  `Unavailable` instead.
- **Close:** after one of the four framing errors (`Oversize`,
  `UnknownKind`, `Truncated`, `NotRelayed`) the node (or relay) writes it,
  then closes the QUIC stream (finishes its side and stops reading), or
  the whole connection on a byte stream, whose framing it may no longer
  trust: answers in flight on that connection are dropped. A well-behaved
  client never meets one. **`Unavailable` does not close** [orchestrator,
  Q-D]: the framing is intact, so it is answered under its id and the
  channel goes on, its other requests in flight with it (7.13's path
  refresh shares a `vos-api` channel).
- **Order:** over QUIC, one request per bidirectional stream: the client
  writes one frame and finishes; the node answers one frame and finishes.
  Over a byte stream, the node reads frames in order and starts each as
  it arrives, answering each when it is done, out of order; it writes an
  answer frame whole, never interleaved with another. No order holds
  between two requests in flight: a client that needs one (a session's
  calls, by sequence) waits for the first answer, as it does over HTTP
  today. Reading in order means a frame that trickles in stalls the frames
  behind it on that connection for up to its deadline: a byte stream is
  the co-located gateway's, or a local tool's, which stalls only itself.
- **Deadlines:** a frame must arrive within 60 s of its first byte (the
  HTTP ingress's `REQUEST_DEADLINE`), on every transport and on the
  `vos-api` channel; a QUIC connection idle 30 s closes; a socket
  connection has no idle limit (local, file-mode access).
- **The client's side:** an answer body past 16 MiB (today's
  `MAX_ANSWER`) is refused before it is read, and the connection closed.

## 3. The kinds

Bodies and answers in SCALE. `Agent` is `AgentId`, a `u32`. "HTTP" is the
gateway's route, today's the node's. **Limit** is the body's, in bytes,
checked from the header. Ranges group the senders: `0x00xx` unsigned
reads, `0x01xx` a client's signed requests, `0x02xx` operator requests;
the table, not the range, is the rule.

| kind | name | HTTP | body | answer | limit |
|---|---|---|---|---|---|
| `0x0001` | `NodeKey` | `GET /` | empty | `NodeId` | 0 |
| `0x0002` | `Time` | `GET /time` (new) | empty | `u64`, ms by the node's clock | 0 |
| `0x0003` | `AgentInfo` | `GET /agents/{a}` | `Agent` | `Option<AgentInfo>` | 4 |
| `0x0004` | `Schema` | `GET /agents/{a}/instances/{i}/schema` | `(Agent, InstanceId)` | `Option<Schema>` | 8 |
| `0x0101` | `Call` | `POST /agents/{a}/calls` | `(Agent, Call)` | `Response` | 69,636 |
| `0x0102` | `Query` | `POST /agents/{a}/queries` | `(Agent, QueryCall)` | `Response` | 69,636 |
| `0x0103` | `Workflow` | `POST /agents/{a}/workflows` | `(Agent, WorkflowRead)` | `Response` | 69,636 |
| `0x0104` | `Credentialed` | `POST /agents/{a}/credentialed` | `(Agent, Credentialed)` | `Response` | 1,642,496 |
| `0x0201` | `Stats` | `GET /stats` | `Operated` of empty | `Response` | 4,252 |
| `0x0202` | `Status` | `GET /agents/{a}/status` | `Operated` of `Agent` | `Response` | 4,252 |
| `0x0203` | `CreateAgent` | `POST /agents` | `Operated` of `Create` | `Response` | 69,792 |
| `0x0204` | `CreateRepresentative` | `POST /representative` | `Operated` of `Create` | `Response` | 69,792 |
| `0x0205` | `Install` | `POST /agents/{a}/install` | `Operated` of `(Agent, Install)` | `Response` | 67,113,120 |
| `0x0206` | `Replace` | `POST /agents/{a}/replicas` | `Operated` of `(Agent, Replace)` | `Response` | 69,792 |
| `0x0207` | `Grant` | `POST /agents/{a}/roles` | `Operated` of `(Agent, Grant)` | `Response` | 69,792 |
| `0x0208` | `Reports` | `POST /agents/{a}/reports` | `Operated` of `(Agent, bool)` | `Response` | 69,792 |

`0x0000` is never assigned; a kind's number never changes or returns.
`0xffff` is the frame error's, an answer only: as a request it is
`UnknownKind`. `0x0104`, the credentialed call, is 7.11's: its checks,
in order, are `identity-and-authority.md` §5's (and `node/SECURITY.md`'s);
its body is not large (only an install's is): its verifications are bounded
by the node's verification budget, past which it is answered `Busy`.

- **Who may send each, and what may be repeated:**

  | kind | sender | over `vos-api` | repeated |
  |---|---|---|---|
  | `NodeKey`, `AgentInfo`, `Schema` | any API client | relayed [orchestrator, Q1(b)] | yes: reads |
  | `Time` | any | relayed [decided, S49] | yes |
  | `Query` | any; its key signs it | relayed [decided, S49] | yes: a read |
  | `Workflow` | any; the workflow's owner signs it | no | yes: a read |
  | `Call` | any; its session's key signs it | no | yes: the session's sequence dedupes |
  | `Credentialed` | any; its proof is its authority | no (7.13 sends it over the gateway's s4 facility) | yes: a repeat is answered `Replayed` (S39), not the first outcome |
  | `Stats`, `Status` | an operator key, signed (§4) | no | yes: reads, signed with an expiry, no nonce recorded [orchestrator, Q-B] |
  | the other `0x02xx` | an operator key, signed (§4) | no | no: each nonce once |

  "Any API client" is anyone holding the socket's file mode, or a QUIC
  key in the node's `gateways` (§5). `Stats` and `Status` are operator
  kinds because today's token gates them, though S46's list omits them
  [orchestrator, Q7(a)].
- **The limits** are today's HTTP limits plus the API's fixed additions,
  so a body the HTTP route took always fits its kind and the gateway never
  turns a 200 into a 413 or back: `Call`, `Query`, `Workflow` the HTTP
  body's 69,632 plus 4 for the agent; an operator kind its HTTP limit
  (69,632, or 67,112,960 for an install) plus 4 for the agent where it
  names one, plus `Operated`'s 156 bytes (node 32, key 32, nonce 16,
  expiry 8, the inner body's length 4, signature 64), rounded up to the
  same figure for every operator kind but the install and the two reads;
  `Stats` and `Status` 4 KiB plus 156. `Credentialed` is pin I's 1.5 MiB
  plus `cap::REQUEST` plus 4 KiB (the agent inside the 4 KiB); the
  gateway's HTTP limit for it is 4 less. `MAX_ELF` moves to `vos-wire`
  (`vos_wire::abi::cap::MAX_ELF`), so the API's table pulls no compiler
  into the gateway or 7.13's client facility.
- **Answers are today's bodies,** so the gateway passes them through:
  `NodeKey` the 32 bytes of `GET /`; `AgentInfo` and `Schema` as
  `Option`s, `None` for today's empty 404 (the gateway strips the tag
  byte and sends the rest, never re-encoding); `Response` as today, its
  HTTP status from the same `status` function, moved (§6).
- **An empty inner body** of `CreateAgent` or `CreateRepresentative` is
  `Create::default()`, as today's empty `POST` body is.
- **`Time`** answers the node's clock (`Inner::clock`, wall time in ms),
  unsigned: a relay that lies about it costs a client a new proof
  (`identity-and-authority.md` §5).
- **The credential actor's `path(member)` and `root()`** are `Query`s
  like any other, signed by a key the device library draws for each
  (`identity-and-authority.md` §6); no kind of their own.
- **New `Rejection` variants** (`vos_wire::ingress`): index 9 is
  `Credential(CredentialRefusal)`, 7.11's (pinned in
  `identity-and-authority.md` §5), so 7.10b takes **10**,
  `Operator(OperatorRefusal)`:

  | index | `OperatorRefusal` | HTTP |
  |---|---|---|
  | 0 | `Expiry { now }`: `expires_ms` outside `now ..= now + 120 s` | 403, as `Credential(Expiry)` |
  | 1 | `Replayed`: the `(key, nonce)` of a write kind recorded | 409 |
  | 2 | `SocketOnly`: an operator kind over QUIC before C5; retired since, never sent | 403 |
  | 3 | `OtherNode`: the envelope names another node | 421 |

  An unlisted key keeps `Unauthorized` (6, 401), a bad signature
  `BadSignature` (0, 401); a body that is not an `Operated` is
  `Malformed`.

## 4. Operator requests

[decided, S46]: each operator kind signed by an operator key the node's
config lists, with a nonce and an expiry; the node keeps each nonce until
its expiry; socket-only until built.

- **The envelope,** an operator kind's body:

  ```rust
  pub struct Operated {
      pub node: NodeId,         // the node it is signed for
      pub key: [u8; 32],        // an operator key the node lists
      pub nonce: [u8; 16],      // the operator's, at random
      pub expires_ms: u64,      // by the node's clock
      pub body: Vec<u8>,        // the kind's request, in SCALE
      pub signature: [u8; 64],  // ed25519 by `key`
  }
  ```
  The key signs
  `"vos/operator/1" ‖ node ‖ kind ‖ nonce ‖ expires_ms ‖ body`: `node`
  the addressed node's `NodeId` (32 bytes), `kind` 2 bytes LE,
  `expires_ms` 8 LE, `body` as SCALE (a `u32` LE length, then the bytes),
  in `ingress.rs`'s `message` form (domain, then an identity, then the
  fields). A request is good at one node for one kind: a relay cannot
  send it to another, and a node's own nonce store is enough. The
  envelope names its node (the review's M1) so a relay can route it to
  the one node it is signed for, and that node refuses it as
  `Operator(OtherNode)` before any signature check.
- **The node's checks, in order:** the frame; the envelope's fixed
  88-byte prefix present (`Malformed`); `node` is this node
  (`Operator(OtherNode)`); `key` listed (`Unauthorized`);
  `now ≤ expires_ms ≤ now + 120 s` (`Operator(Expiry { now })`); then, off
  the node's thread as `Ingress::signed` does, the envelope decoded
  (`Malformed`) and its signature checked (`BadSignature`), so a body as
  large as an install is copied only for a listed key's request to this
  node in time; the inner body decodes (`Malformed`); for a write kind,
  the nonce recorded (below); then the command runs as today. The
  signature comes before the store, so junk fills nothing.
- **Recording a nonce** (the review's M4) is one step on the node's
  thread, after the signature returns: an insert of `(key, nonce)` if
  absent (`Operator(Replayed)` if present), so two copies of one request
  in flight on the multiplexed socket cannot both pass; then the row is
  written and synced (`fsync`) before the command runs, so a request
  whose command ran is refused after a restart (`Unavailable` if the
  write fails, the command not run). The reads (`Stats`, `Status`) record
  none [orchestrator, Q-B]: a replayed read within 120 s discloses nothing
  the first did not, to a holder of the first, and `vos-scale`'s
  collector polls `Status` of every placed agent each interval, past any
  bound at T3's 10^4 agents.
- **The nonce store:** a node-local table in the node's store (fjall, not
  replicated), `key ‖ nonce → expires_ms`, loaded at start, swept as
  entries expire. Durable [orchestrator, Q4(a)]. An entry is forgotten
  only once the node's clock is past its expiry by more than the 120 s
  horizon, so a clock stepped back by up to the horizon still refuses
  the replay (the Fable review's L1). At most 65,536 live entries; past
  them, `Busy`. The listed keys are the node's operators,
  all trusted alike: the bound is shared, not per key.
- **The keys,** in the node's TOML (`node/cli/src/config.rs`):
  `operators = ["<hex>", …]`. The node also makes `operator.key` in its
  data directory at its first start (mode 0600) with `operator.pub`
  beside it, and lists that public key unless `local_operator = false`,
  so the CLI on the node's host signs as today's token file allows
  [orchestrator, Q3(a)]; after the first start the node reads only
  `operator.pub`. `admin.token` goes with the node's HTTP (C10). The
  client's `Operator` learns the node's time from `Expiry { now }`, as
  `with_learned_time` does for queries, and signs again once, with the
  same nonce: a relay that holds the first copy back and forges the
  refusal gets the command run once between the two (the Opus review's
  M3). A signed command may go again on a fresh connection, its nonce
  deduping it: if the first copy ran before the kept connection failed,
  the resend answers `Replayed` (409), not the command's outcome, which
  the operator reads from the node (the Fable review's L10).
- **The interim** [decided, S46]: until the envelope lands (commit C5,
  §9), operator kinds take their bare body, on the unix socket only; over
  QUIC they are answered `Rejected(Operator(SocketOnly))`. Once it lands,
  every operator kind is signed on both transports and an unsigned one is
  refused everywhere, the socket included: a co-located gateway on the
  socket must hold no authority either. `api::handle`'s transport
  argument then matters only to the node's own HTTP, whose bearer token
  admits a bare operator body until that HTTP is deleted (C10);
  `SocketOnly` stays a retired index.
- **The gateway and s4's console only relay** (S46): they carry an
  `Operated` the operator built in their own client; nothing they keep
  can be replayed past its nonce, sent to another node, or outlive its
  expiry.

## 5. The transports

- **The unix socket** [decided, S41]: `api_socket` in the node's config,
  by default `<data>/api.sock`, made at start with mode `api_socket_mode`
  (default 0660: the node's user and group). A lock file beside it
  (`api.sock.lock`, an exclusive `flock` held for the node's life) decides
  between twins: the node that holds it removes a stale socket file and
  binds; one that cannot take it refuses to start. The file mode is the
  access; no peer credentials are read. Byte-stream frames with ids,
  multiplexed (§2).
- **QUIC with mutual TLS** [decided, S41]: a second QUIC endpoint on its
  own UDP port (`api_listen`), apart from the peer endpoint
  [orchestrator, Q6(a)]: its own allowlist, bidirectional streams (the
  peers' have none), and a thread of its own, so API load never shares the
  consensus network's. TLS 1.3, raw ed25519 keys both ways, the node's own
  key as the server's, ALPN `vos-api/1`; the client's key checked at the
  handshake against `gateways = ["<hex>", …]` in the node's config, an
  unlisted key or another ALPN refused there; no resumption, no tickets,
  as the peers'. `vos-net` exposes its TLS builders (the ALPN and the
  allowlist as parameters) and its executor, the runner quinn's runtime
  needs (`vos_net::api`); the endpoint itself lives in the node
  (`node/host/src/api/`). The gateway enables quinn's `runtime-tokio`
  beside `vos-net`'s `runtime-smol`: each endpoint names its runtime
  explicitly, so the unified features change nothing in the node. A
  `gateways` key is a transport admission, no authority: a driver of
  `vos-scale` or a remote `vos` is listed the same way.
- **Limits** (the review's M5): `api_connections` connections per
  transport (default today's `ingress_connections`, 1,024), more refused
  at accept (the socket) or the handshake (QUIC); `api_in_flight`
  requests in flight per connection on both transports (default 1,024),
  past which the node stops reading the socket, and QUIC's
  `max_concurrent_bidi_streams` (set to it) holds the client back. T1's
  in-flight count at its p99 is about 250 (5,000/s × 50 ms), so one
  connection never caps a co-located gateway or a driver below the
  node's own; the gateway still keeps a few socket connections a node, and
  the numbers are recorded with S50's re-measure. The verification budget
  of 7.11 (`Busy`) is per node. Over QUIC a client proves its address
  first (a Retry), at most 64 handshakes are under way, 8 from one
  address (an IPv6 /64), each within 10 s, and `api_connections` counts
  connections that shook hands. A host that passed Retry needs no key to
  hold a handshake's place until the TLS verdict, so the API's port is
  for gateways and drivers: a deployment firewalls `api_listen` to them
  (the Fable review's L3). At most four large bodies (an install's, past
  `vos_api::LARGE`) are held at once across the socket and QUIC: the
  socket reads a large frame's body only once it holds a place, its
  deadline running from then, and QUIC answers `Unavailable` from the
  header (L6). A frame's deadline runs from its own first byte. After a
  frame error on the socket, the requests in flight run on detached
  while the connection's place is given back, so a local client can have
  more running than `api_connections × api_in_flight`; the socket's mode
  bounds who can (L2). Queries waiting for their
  replica to reach their floor are at most `floor_waits` (256): one past
  them is answered `Behind` at once, so slow reads cannot hold a
  connection's in-flight places for long.
- **One handler:** `Ingress::handle`'s routing becomes
  `api::handle(kind, body, transport) → answer bytes`, which both
  transports and, while it exists, the node's HTTP call: the HTTP ingress
  becomes a translation onto it, the gateway's translation (§6), so the
  differential test compares one table run two ways.

## 6. The gateway

- **Layout** [orchestrator, Q-E]: three crates, the node depending on none
  that pulls tokio, russh or s4.
  - `vos-api` (`node/api`): the frame codec (sans-IO: a header type, an
    incremental reader, the writer), `Kind` with its limits, senders and
    relay set, `FrameError`, `Operated` and its message; a client of the
    node API over a byte stream (multiplexed) and over QUIC (a stream a
    request), generic over futures-io, the QUIC side over quinn's own
    API whatever its runtime. The node, the gateway, the client and the
    7.13 client facility share it. The multiplexed client only queues a
    whole frame; its task writes it, so a request cancelled at any point
    leaves no part of a frame on a stream others share.
  - `vos-http` (`node/http`): the HTTP server (`http.rs`, moved from the
    node and made runtime-neutral: an accept stream and a spawn function
    in place of `smol::net::TcpListener` and the node's runtime), the
    public TLS (`tls.rs`'s server half, moved), and the route table (path
    parsing, `status`, the operator header, the answer's HTTP form). The
    node's HTTP imports it until C10 deletes that import; the gateway
    imports it for good.
  - `vos-gateway` (`node/gateway`), a library and the binary
    `vos-gateway`, depending on `vos-api`, `vos-http`, `vos-wire`,
    `vos-net`'s TLS builders and `s4-server`, never on the node.
- **Runtime:** tokio. s4-server is tokio and russh and installs no
  runtime; the binary builds a multi-threaded tokio runtime, serves HTTP
  through `tokio_util::compat` over the runtime-neutral server, and dials
  nodes with quinn's tokio runtime. One runtime, no bridge; the codec is
  sans-IO, so the smol node and the tokio gateway share it.
- **HTTP, byte for byte:** paths, bodies and statuses exactly as
  `ingress.rs` gives them, by the moved route table: `GET` bodies read
  and counted against the limit, then unused, as today; an empty `POST
  /agents` or `/representative` body as `Create::default()`; an id that
  is not a `u32` answered as today (an encoded `NoAgent` with 404 on the
  request routes, an empty 404 on `GET /agents/{a}` and the schema);
  unknown paths an empty 404; 411 on chunked bodies, 413 past a limit
  (the install's by the path's suffix, even on an unknown path), 431 past
  a 16 KiB head, `100 Continue` as today. New routes: `GET /time`, and
  7.11's `POST /agents/{a}/credentialed`.
- **Large bodies** (the Fable review's M1): `vos-http` holds at most four
  bodies past its ordinary limit (an install's) at once, from every
  connection (`Limits::large`), and answers a request past them 503 from
  its head, the body unread; the node's own HTTP takes the same budget.
  Before that, the gateway answers an operator's route from its head, as
  the whole request would be answered: 401 with no `Operated` header (or
  one that is not 152 bytes), 421 `Operator(OtherNode)` for an envelope
  naming no upstream. Neither answer depends on the body, so the
  differential corpus is unchanged, and a request with no plausible
  envelope never reaches the budget. A refused body past the ordinary
  limit, or one the client waits for `100 Continue` to send, is never
  read: the connection closes after the answer.
- **The operator routes** [orchestrator, Q-A; the review's M2]: today's
  bearer token is the node's, and a gateway holding it would hold
  authority. So the routes keep today's methods, paths and bodies byte for
  byte, and the envelope's fields ride in the header where the token was:

  `Authorization: Operated <base64 of node ‖ key ‖ nonce ‖ expires_ms ‖ signature>`

  (152 bytes, `expires_ms` 8 LE, standard base64 with padding). The
  gateway composes the frame's `Operated` from them, its inner body
  `agent ‖ body` for a route naming an agent (`Status`'s inner body the
  agent alone), the body alone for `POST /agents` and `/representative`,
  empty for `GET /stats`; the operator's client signs the same bytes. So
  the path's agent is the signed one, and `Stats` and `Status` keep their
  empty `GET`s. A path whose id is not a `u32` is answered as today's
  authorized request is (an encoded `NoAgent`, 404), before any frame: the
  gateway cannot form one. A missing or unreadable header is
  `Rejected(Unauthorized)`, 401, as a wrong token is today. Until C10 the
  node's own HTTP takes either a bearer token (its own, as today) or the
  same `Operated` header, through the same table.
- **Its configuration** (a TOML file): the upstream nodes, each by its key
  and API address (`quic://host:port`, or `unix:/path` for a co-located
  one); its key file `gateway.key` (its QUIC client key, which the nodes
  list in `gateways`, and the key its own-key HTTPS presents); the HTTP
  listener and public TLS from PEM files or its own key; the per-address
  limits; the SSH port, host key and limits; `app.key`.
- **Leader-aware routing:** a request goes to the agent's leader as last
  learned (`Call`, `Credentialed`), any upstream (reads), or the one node
  it is signed for (operator kinds, by the envelope's `node`, never
  redirected; an envelope naming no upstream is answered `Operator(OtherNode)`
  by the gateway, 421). On `NotLeader { leader: Some(c) }` or
  `Elsewhere { replicas }` the gateway resends the same frame to the
  upstream whose key is `c.node` (or the first replica it has), up to 4
  times, as the client does; with no such upstream, or past 4, the answer
  goes to the HTTP client as is (421). Resending is safe for every kind it
  redirects (§3's "repeated"). `Busy` is passed on, not retried: the
  client's backoff stays the client's. An upstream that fails mid-request
  is answered `Unavailable` (503), never resent. A dial holds no lock a
  request with a connection open waits on, and one dial is under way at
  a time per upstream; an upstream whose dial failed is down for a
  backoff (1 s, doubling to 8 s), answered `Unavailable` at once while it
  lasts, and reads in turn, and calls to a learned leader, skip an
  upstream that is down or whose dial has been under way for over 250
  ms while another is ready: one dead node delays only the requests that
  must go to it (the Fable review's M2).
- **Per-address limits,** before any authentication or decoding:
  connections per source address (default 64), and requests a second per
  address with a burst (default 200, 400), past which HTTP answers 429
  from the request's head, its body unread, and SSH refuses the channel; s4-server's `ServerLimits` bounds its
  connections and handshakes before authentication. s4's per-identity
  session caps mean nothing under ephemeral keys: the per-address limits
  are the bound (the review's L9).
- **The SSH port** hosts s4 (7.13's screens) and the **`vos-api`
  subsystem** [decided, S49]: under any key, a fresh ephemeral one
  expected, the gateway's authenticator taking any public key (7.13 moves
  no policy: C8 sets it); a byte-stream channel of frames (with ids). The
  gateway reads each header, answers `NotRelayed` for any kind outside the
  relay set (`NodeKey`, `Time`, `AgentInfo`, `Schema`, `Query`) without
  reading its body or sending anything to a node, checks the limit, then
  relays the frame to a node under a fresh upstream id and maps the answer
  back. At most 16 requests in flight a channel, past which it stops
  reading; each frame within 60 s of its first byte. A channel holds a
  place among its address's connections, as an HTTP connection does; each
  frame takes a token of its address's rate (past it, the channel closes)
  and, while in flight, a place among its address's (past them, it is
  answered `Unavailable`). An IPv6 address counts by its /64. s4-server gains a hook
  for a named subsystem with a raw channel (`Server::subsystem(name,
  handler)`), in the s4 repository (S40 makes s4 Claude's to change),
  under s4's own rule for channel input: the SSH loop's `data` callback
  never awaits, its queue `try_send`s and closes the connection when full.
- **The s4 app's client key:** `app.key`, an ordinary VOS client key
  apart from `gateway.key`, with which the gateway's s4 app sends the
  claims (`claim(member)`, `claim_row`) of members with no key of their
  own; its authority is the registrar's invitations, which name the
  digests. 7.10b loads it and gives apps a node-API client on it; the
  claim screens are 7.13's. Its calls run in one session per agent, so the
  app sends one claim at a time to an agent, in order.
- **No authority** [decided, S41]: the node verifies every signature and
  proof and runs every ingress check. A compromised gateway can drop,
  delay or reorder requests and read what it relays; it can forge
  nothing, replay no operator request, and send a credentialed call only
  once (its binding).

## 7. The client's seam and the migration

- **The seam** is `node/host/src/client/http.rs`: beside it
  `client/api.rs`, a blocking node-API transport over `vos-api`'s codec
  (the socket, or QUIC through quinn's smol runtime). `Http` becomes one
  arm of a `Transport` enum the `Client` and `Operator` hold. A `Target`
  takes `unix:/path` and `quic://host:port` (pinning the node's key,
  required) beside `http://` and `https://`. `Operator` signs `Operated`
  with an operator key: over the API as the body, over HTTP in the
  `Authorization` header; a token over HTTP while the node's HTTP exists.
- **Pinning:** over QUIC the client pins the node's key at the handshake,
  and `GET /`'s check (`NotTheNode`) stays the node-API transport's.
  Through a gateway a client trusts the gateway: `Trust::Gateway(key)`
  pins the gateway's own-key TLS (or `Trust::Ca` its CA's), keeps that pin
  across redirects (the review's M8), and skips `NotTheNode`, since `GET
  /` still answers a node's key [orchestrator, Q5(a)]. Every node's
  `ingress` column names its gateway, so a redirect through a gateway
  converges on the gateway, which routes again.
- **Redirects over the API** need a node's API address for a `Contact`:
  the node-API client takes them from its own table, by node key (its
  config, or `vos-scale`'s inventory); `Contact` and the space file are
  unchanged.
- **The order:**
  1. the host's tests and the checker over both transports, chosen by
     the harness, the HTTP arm through the gateway once it exists;
  2. `vos` (`node/cli`): `--node unix:…` and `quic://…`, operator
     commands signing with `operator.key`;
  3. `vos-scale`: its drivers' pool becomes one QUIC connection a node,
     a stream a request, the driver's key listed in each node's
     `gateways` by `deploy`; `collect` signs `Stats` and `Status` with the
     harness's operator key; the gateway's cost a row of its own (S41);
  4. the end-to-end suites through the gateway.
- **The differential test** runs while both exist (§8).
- **Deleting the node's HTTP** (`ingress.rs`, its `vos-http` import,
  `admin.token`, the `--tls` flags, which move to the gateway) waits on
  S50: the gateway carries every route, the HTTP tests pass through it,
  and 7.6's final scale run is done, or T1 is re-measured over the node
  API and both recorded [decided].

## 8. The tests

From §7.10b's list, then this brief's additions and the review's (L12).

| # | test | where |
|---|---|---|
| 1 | every route through the gateway answers as the node's HTTP: one corpus (each route, valid, malformed, a bad id, oversize by one, unknown paths, `Expect`, chunked; the operator routes with an `Operated` header, a bad one, none) sent to one node by its own HTTP and through a gateway on its socket; statuses and bodies equal | gateway |
| 2 | each kind's body one past its limit refused `Oversize { limit }` from the header alone (the test sends the header and no body) | node, gateway |
| 3 | an unknown kind, `0xffff` among them, `UnknownKind`; a length below the header `Truncated` (id 0 on a stream); a body cut short then the write side shut, `Truncated`; each followed by the stream's or connection's close | node |
| 4 | a QUIC client with an unlisted key, and one with another ALPN, refused at the handshake | node |
| 5 | a gateway that flips a byte of a signed call's arguments: `BadSignature` from the node | gateway |
| 6 | an operator kind over QUIC `Operator(SocketOnly)` before C5 | node |
| 7 | after C5: an operator kind unsigned (`Malformed`), by an unlisted key (`Unauthorized`), with a bad signature (`BadSignature`), signed for another node (`OtherNode`), replayed (`Replayed`), two copies at once (one runs), replayed after a restart, expired and too far ahead (`Expiry`), each refused, over both transports; a read replayed answered; the store's bound answering `Busy` | node |
| 8 | over `vos-api`, each kind outside the relay set answered `NotRelayed`, the channel closed, and the node's count of API frames unchanged; an upstream gone answered `Unavailable` with the channel kept; 16 in flight on one channel | gateway |
| 9 | the gateway following `NotLeader` and `Elsewhere`; passing 421 past 4 or for an unknown key; never redirecting an operator kind; the HTTP client pinning the gateway and following a 421 through it | gateway |
| 10 | the end-to-end suites through the gateway | e2e |
| 11 | out of order on the socket: a `Workflow` read waiting 2 s and a `Time` sent after it, `Time` answered first, each by its id | node |
| 12 | `api_in_flight` on one socket connection: the next read only as one ends | node |
| 13 | `Time` within a few ms of the node's clock; over `vos-api` too | node, gateway |
| 14 | the codec: pinned encodings of headers, `FrameError`, `Operated`'s message; proptests of the incremental reader against split reads; fuzz targets for the reader and `Operated`'s decode in `just fuzz` | `vos-api` |
| 15 | per-address limits: past the burst, 429 | gateway |
| 16 | `vos-scale`'s localhost inventory driving over the node API, a short run | scale |
| 17 | `api_connections` refused at accept (the socket) and at the handshake (QUIC); the 60 s frame deadline on both; a stale socket file replaced, and a twin refused by the lock | node |
| 18 | the gateway's 413 never reaching the node (its count of API frames unchanged) | gateway |

## 9. The commits

Each one reviewable alone, `just check` green at each; days of an
implementing agent.

| | commit | days |
|---|---|---|
| C1 | `vos-api`: the codec, `Kind` and its table, `FrameError`, `Operated`; `Rejection::Operator` and `MAX_ELF` in `vos-wire`; test 14 | 1.5 |
| C2 | the node: `api::handle` from `Ingress::handle`; `vos-http` with the route table, `status`, `http.rs` runtime-neutral and `tls.rs`'s server half; the node's HTTP a translation onto `api::handle`; the ingress tests unchanged and green | 2 |
| C3 | the node: the unix socket, `Time`, operator kinds bare on it; tests 2, 3, 11, 12, 13, 17's socket half | 1.5 |
| C4 | `vos-net`'s TLS builders and executor; the node's QUIC endpoint, `gateways`; tests 4, 6, 17's QUIC half | 2 |
| C5 | signed operator requests: `Operated` checks, `operators`, `operator.key`, the nonce store; operator kinds on both transports; test 7 | 2 |
| C6 | the client: `client/api.rs`, `Transport`, the targets, `Trust::Gateway`, `Operator` signing; `vos`'s flags; the checker; the host's tests over both transports | 2.5 |
| C7 | `vos-gateway`'s binary: tokio, config, HTTP onto the API, leader-following, limits, public TLS; tests 1, 5, 9, 15, 18 | 3 |
| C8 | s4: the named-subsystem hook (its repository, on its `vos` branch, under its own gate); the gateway's SSH port, `vos-api`, `app.key`; tests 8, 13 | 2, plus s4's review and the rev pin |
| C9 | `vos-scale` over the node API, the gateway's cost row; the end-to-end suites through the gateway; tests 10, 16 | 2 |
| C10 | (gated by S50) the node's HTTP deleted | 0.5 |

About 19 days, past the plan's 2–3 weeks by a few days. C10 lands when
S50's gate is met, which may be after the step's review. Fable reviewed
this brief before C1; the Opus review takes the branch.

**s4's pin** [owner, Q-C]: s4 is a git dependency on codeberg's
`Virto/s4`, pinned by rev, from its `vos` branch, created from the
owner's `main` once pushed; the subsystem hook lands on that branch
first. The gateway pins it at `cee80d95` (the hook `bd3c435` and an
advisory fix), behind its `ssh` feature, off by default; s4's crates ask
Rust 1.94.1, which the workspace's nightly builds with
`--ignore-rust-version` (`just test-gateway-ssh`).

## 10. Decisions

The brief's ten questions and the review's five, each answered: the
orchestrator's calls unless marked the owner's.

1. **The `vos-api` relay set:** S49's `Query` and `Time`, plus `NodeKey`,
   `AgentInfo` and `Schema` (Q1(b)): public reads the node serves
   unsigned to anyone today; an anonymous relay lying about `AgentInfo`
   costs a `BadSignature` and nothing more, and 7.13's client still pins
   what S48 pins.
2. **Operator routes over the gateway's HTTP** (Q2, refined by Q-A): the
   `Operated` envelope's fields in the `Authorization` header, the body
   and path byte for byte today's, the gateway composing the signed
   `agent ‖ body` (§6).
3. **The local operator key** (Q3(a)): `operator.key` and `operator.pub`,
   made at first start and listed by default, replace `admin.token`;
   every operator kind is signed on every transport once C5 lands.
4. **The nonce store** (Q4(a)): durable, in the node's store, recorded
   atomically and synced before the command runs (M4).
5. **Addresses and pinning through a gateway** (Q5(a)): the node-API
   client maps contacts by key from its own table; HTTP clients through a
   gateway pin it with `Trust::Gateway` (M8); the space file's `ingress`
   column names each node's gateway.
6. **The API's QUIC endpoint** (Q6(a)): its own UDP port and thread, its
   bidi cap `api_in_flight` (M5).
7. **`Stats` and `Status`** (Q7(a), refined by Q-B): operator reads,
   signed with an expiry, no nonce recorded (M3); the write kinds take a
   nonce.
8. **s4 as a dependency** (Q8, Q-C) [owner]: a git dependency pinned by
   rev, from a `vos` branch on codeberg's `Virto/s4`, created from the
   owner's `main` once that is pushed; the hook lands there first (§9).
9. **`FrameError::Unavailable`** (Q9, Q-D): added, answered under its id
   without closing the channel or stream (M7).
10. **The binding digest's `arguments`** (Q10): hashed as the codec writes
    them, a `u32` LE length then the bytes; `identity-and-authority.md`
    §5, `proving.md` §8 and pin I say so, "compact" dropped.
11. **Where the node's HTTP lives until C10** (Q-E): `vos-http`, imported
    by the node and the gateway; the node never depends on tokio, russh or
    s4 (M6).
