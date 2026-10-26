# The node API and the gateway

The brief of slice 7's step 7.10b (`slice-7-mobile.md`), written before
any code so Fable reads the frame grammar and the kind table first. The
node keeps one binary API; its HTTP, public TLS and front-end concerns
move to a gateway that holds no authority [decided, S41]. It builds on
`identity-and-authority.md` §5–§6 (the credentialed call, operator
requests) and the owner's S40, S41, S46, S49 and S50
(`research/slice-7/owner-decisions.md`).

Tags as in the plan: [decided] the owner's; [proposed] open to review;
[measured] by a run. Everything not tagged is [proposed].

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
  carries the token. `vosx`, the checker, the host's tests and
  `vos-scale` use it; `vos-scale`'s drivers keep their own async pool of
  HTTP connections (`tools/scale/src/engine/pool.rs`), signing with
  `signed_call` and `signed_query`.
- **The peer network** (`node/net`) is QUIC (quinn, `runtime-smol`) with
  TLS 1.3 and raw ed25519 public keys (RFC 7250) on both sides, ALPN
  `vos/1`, the accepting side checking the dialer against the configured
  peers, no session resumption; unidirectional streams only, on a
  network thread of its own.
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
  throughout, as the codec. A `u32` length bounds a frame at 4 GiB, past
  every limit (the largest, an install, is 64 MiB plus 4 KiB plus 128).
- **An answer frame** repeats the request's header, its `kind` and (on a
  stream) its `id`, then the answer's body. A request has exactly one
  answer frame, or none if the connection ends first.
- **Ids** are the client's: the node echoes them and keeps no table, so
  an id reused while in flight gives the client two answers it cannot
  tell apart. Clients count from 1. A frame error the node cannot tie to a
  request (a length too short to hold an id) carries id 0.
- **Read before decoding,** in this order, each failure a frame error:
  1. `length` below the header's rest (2, or 10): `Truncated`;
  2. `kind` not in the table: `UnknownKind`;
  3. on a relay, `kind` not relayable there: `NotRelayed` (§6);
  4. the body (`length` less the header's rest) past the kind's limit:
     `Oversize { limit }`, before any body byte is read or allocated;
  5. the stream or connection ending before `length` bytes:
     `Truncated` (answered if the peer still reads, else nothing).

  Then the body is decoded exactly (`decode_exact`). A body that does not
  decode is not a frame error: it is the kind's own answer, for kinds
  answering `Response` a `Rejected(Malformed)` (HTTP 400), as today.
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
  `Unavailable` is added to the plan's four: a relay whose upstream
  fails mid-request must answer every kind, and three kinds answer types
  with no `Unavailable` of their own (`NodeKey`, `Time`, the `Option`s).
  A node answers the `Response` kinds' own `Unavailable` instead.
- **Close:** after a frame error the node (or relay) writes it, then
  closes the QUIC stream (finishes its side and stops reading), or the
  whole connection on a byte stream, whose framing it may no longer
  trust: answers in flight on that connection are dropped. One rule for
  every variant; a well-behaved client never meets one.
- **Order:** over QUIC, one request per bidirectional stream: the client
  writes one frame and finishes; the node answers one frame and finishes.
  Over a byte stream, the node reads frames in order and starts each as
  it arrives, answering each when it is done, out of order; it writes an
  answer frame whole, never interleaved with another. No order holds
  between two requests in flight: a client that needs one (a session's
  calls, by sequence) waits for the first answer, as it does over HTTP
  today.
- **Deadlines:** a frame must arrive within 60 s of its first byte (the
  HTTP ingress's `REQUEST_DEADLINE`); a QUIC connection idle 30 s
  closes; a socket connection has no idle limit (local, file-mode
  access).
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
| `0x0104` | `Credentialed` | `POST /agents/{a}/credentialed` | `(Agent, Credentialed)` | `Response` | 1,642,496 (reserved, 7.11) |
| `0x0201` | `Stats` | `GET /stats` | `Operated` of empty | `Response` | 4,220 |
| `0x0202` | `Status` | `GET /agents/{a}/status` | `Operated` of `Agent` | `Response` | 4,220 |
| `0x0203` | `CreateAgent` | `POST /agents` | `Operated` of `Create` | `Response` | 69,760 |
| `0x0204` | `CreateRepresentative` | `POST /representative` | `Operated` of `Create` | `Response` | 69,760 |
| `0x0205` | `Install` | `POST /agents/{a}/install` | `Operated` of `(Agent, Install)` | `Response` | 67,113,088 |
| `0x0206` | `Replace` | `POST /agents/{a}/replicas` | `Operated` of `(Agent, Replace)` | `Response` | 69,760 |
| `0x0207` | `Grant` | `POST /agents/{a}/roles` | `Operated` of `(Agent, Grant)` | `Response` | 69,760 |
| `0x0208` | `Reports` | `POST /agents/{a}/reports` | `Operated` of `(Agent, bool)` | `Response` | 69,760 |
| `0xffff` | frame error | | | `FrameError` | |

`0x0000` is never assigned; a kind's number never changes or returns.

- **Who may send each, and what may be repeated:**

  | kind | sender | over `vos-api` | repeated |
  |---|---|---|---|
  | `NodeKey`, `AgentInfo`, `Schema` | any API client | not relayed [decided, S49]; see Q1 | yes: reads |
  | `Time` | any | relayed [decided, S49] | yes |
  | `Query` | any; its key signs it | relayed [decided, S49] | yes: a read |
  | `Workflow` | any; the workflow's owner signs it | no | yes: a read |
  | `Call` | any; its session's key signs it | no | yes: the session's sequence dedupes |
  | `Credentialed` | any; its proof is its authority | no (7.13 sends it over the gateway's s4 facility) | yes: a repeat is answered `Replayed` (S39), not the first outcome |
  | `Stats`, `Status` | an operator key, signed (§4) | no | yes: reads, but each nonce once |
  | the other `0x02xx` | an operator key, signed (§4) | no | no: each nonce once |

  "Any API client" is anyone holding the socket's file mode, or a QUIC
  key in the node's `gateways` (§5). `Stats` and `Status` are operator
  kinds because today's token gates them, though S46's list omits them
  (Q7).
- **The limits** are today's HTTP limits plus the API's fixed additions,
  so a body the HTTP route took always fits its kind and the gateway never
  turns a 200 into a 413 or back: `Call`, `Query`, `Workflow` the HTTP
  body's 69,632 plus 4 for the agent; an operator kind its HTTP limit
  (69,632, or 67,112,960 for an install) plus 4 for the agent where it
  names one, plus `Operated`'s 124 bytes (key 32, nonce 16, expiry 8, the
  inner body's length 4, signature 64), rounded up to the same figure for
  every operator kind but the install and the two reads; `Stats` and
  `Status` 4 KiB plus 124. `Credentialed` is pin I's 1.5 MiB plus
  `cap::REQUEST` plus 4 KiB (the agent inside the 4 KiB); the gateway's
  HTTP limit for it is 4 less.
- **Answers are today's bodies,** so the gateway passes them through:
  `NodeKey` the 32 bytes of `GET /`; `AgentInfo` and `Schema` as
  `Option`s, `None` for today's empty 404 (the gateway strips the tag
  byte and sends the rest, never re-encoding); `Response` as today, its
  HTTP status from the same `status` function, moved (§5).
- **`Time`** answers the node's clock (`Inner::clock`, wall time in ms),
  unsigned: a relay that lies about it costs a client a new proof
  (`identity-and-authority.md` §5).
- **The credential actor's `path(member)` and `root()`** are `Query`s
  like any other, signed by a key the device library draws for each
  (`identity-and-authority.md` §6); no kind of their own.
- **New `Rejection` variants** (`vos_wire::ingress`): index 9 is
  `Credential(CredentialRefusal)`, 7.11's (pinned in
  `identity-and-authority.md` §5), so 7.10b takes **10**,
  `Operator(OperatorRefusal)`, with `Expiry { now }` 0, `Replayed` 1,
  `SocketOnly` 2. HTTP: `Expiry` 400, `Replayed` 409, `SocketOnly` 403.
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
  fields). A request is good at one node only: a relay cannot send it to
  another, and a node's own nonce store is enough.
- **The node's checks, in order:** the frame; the transport (§5's
  interim); `Operated` decodes (`Malformed`); `key` listed
  (`Unauthorized`); `now ≤ expires_ms ≤ now + 120 s`
  (`Operator(Expiry { now })`); the signature, off the node's thread as
  `Ingress::signed` does (`BadSignature`); the inner body decodes
  (`Malformed`); `(key, nonce)` not recorded (`Operator(Replayed)`); the
  nonce recorded until `expires_ms`; then the command runs as today. The
  signature comes before the store, so junk fills nothing.
- **The nonce store:** a node-local table in the node's store (fjall, not
  replicated), `key ‖ nonce → expires_ms`, written before the command
  runs, swept as entries expire. Durable, so a request captured before a
  restart is refused after it (Q4). At most 65,536 entries; past them,
  `Busy`. A listed key flooding it harms only its own operator.
- **The keys,** in the node's TOML (`node/cli/src/config.rs`):
  `operators = ["<hex>", …]`. The node also makes `operator.key` in its
  data directory at its first start (mode 0600) and lists its public key
  unless `local_operator = false`, so the CLI on the node's host signs as
  today's token file allows (Q3). `admin.token` goes with the node's HTTP.
- **The interim** [decided, S46]: until the envelope lands (commit C5,
  §8), operator kinds take their bare body, on the unix socket only; over
  QUIC they are answered `Rejected(Operator(SocketOnly))`. Once it lands,
  every operator kind is signed on both transports and an unsigned one is
  refused everywhere, the socket included: a co-located gateway on the
  socket must hold no authority either.
- **The gateway and s4's console only relay** (S46): they carry an
  `Operated` the operator built in their own client; nothing they keep
  can be replayed past its nonce, sent to another node, or outlive its
  expiry.

## 5. The transports

- **The unix socket** [decided, S41]: `api_socket` in the node's config,
  by default `<data>/api.sock`, made at start with mode `api_socket_mode`
  (default 0660: the node's user and group), a stale file replaced when
  nothing listens on it. The file mode is the access; no peer
  credentials are read. Byte-stream frames with ids, multiplexed (§2).
- **QUIC with mutual TLS** [decided, S41]: a second QUIC endpoint on its
  own UDP port (`api_listen`), apart from the peer endpoint (Q6): its
  own allowlist, bidirectional streams (the peers' have none), and a
  thread of its own, so API load never shares the consensus network's.
  TLS 1.3, raw ed25519 keys both ways, the node's own key as the server's,
  ALPN `vos-api/1`; the client's key checked at the handshake against
  `gateways = ["<hex>", …]` in the node's config, an unlisted key or
  another ALPN refused there; no resumption, no tickets, as the peers'.
  `vos-net` exposes its TLS builders for this (`tls::Identity` with the
  ALPN and the allowlist as parameters); the endpoint itself lives in the
  node (`node/host/src/api/`). A `gateways` key is a transport admission,
  no authority: a driver of `vos-scale` or a remote `vosx` is listed the
  same way.
- **Limits:** `api_connections` connections per transport (default
  today's `ingress_connections`), more refused at accept (the socket) or
  the handshake (QUIC); 256 requests in flight per connection, past which
  the node stops reading the socket, and QUIC's
  `max_concurrent_bidi_streams` holds the client back. The verification
  budget of 7.11 (`Busy`) is per node.
- **One handler:** `Ingress::handle`'s routing becomes
  `api::handle(kind, body, transport) → answer bytes`, which both
  transports and, while it exists, the node's HTTP call: the HTTP ingress
  becomes a translation onto it, the gateway's translation (§6), so the
  differential test compares one table run two ways.

## 6. The gateway

- **Layout:** `node/gateway`, crate `vos-gateway`, a library and the
  binary `vos-gateway`. It depends on `vos-api`, `vos-wire`, `vos-net`'s
  TLS builders and `s4-server`, never on the node.
  - `vos-api` (`node/api`, new): the frame codec (sans-IO: a header type,
    an incremental reader, the writer), `Kind` with its limits, senders
    and relay set, `FrameError`, `Operated` and its message; a client of
    the node API over a byte stream (multiplexed) and over QUIC (a stream
    a request), generic over futures-io and quinn's runtime trait. The
    node, the gateway, the client and the 7.13 client facility share it.
  - The gateway's library: the HTTP server (`http.rs`, moved from the
    node and made runtime-neutral: an accept stream in place of
    `smol::net::TcpListener`), the public TLS (`tls.rs`'s server half,
    moved), and the route table (path parsing, `status`), which the
    node's HTTP imports until it is deleted. After that nothing moves.
- **Runtime:** tokio. s4-server is tokio and russh and installs no
  runtime; the binary builds a multi-threaded tokio runtime, serves HTTP
  through `tokio_util::compat` over the runtime-neutral server, and dials
  nodes with quinn's tokio runtime (its `runtime-tokio` feature beside
  `vos-net`'s `runtime-smol`). One runtime, no bridge; the codec is
  sans-IO, so the smol node and the tokio gateway share it.
- **HTTP, byte for byte:** paths, bodies and statuses exactly as
  `ingress.rs` gives them, by the moved route table: `GET` bodies
  ignored; an empty `POST /agents` or `/representative` body as
  `Create::default()`; an id that is not a `u32` answered as today (an
  encoded `NoAgent` with 404 on the request routes, an empty 404 on
  `GET /agents/{a}` and the schema); unknown paths an empty 404; 411 on
  chunked bodies, 413 past a limit, 431 past a 16 KiB head, `100
  Continue` as today. **The exception is the operator routes:** today's
  bearer token is the node's, and a gateway holding it would hold
  authority, so through the gateway their body is the `Operated`
  envelope and no token is read (Q2). New routes: `GET /time`, and 7.11's
  `POST /agents/{a}/credentialed`.
- **Its configuration:** the upstream nodes, each by its key and API
  address (`quic://host:port`, or `unix:/path` for a co-located one); its
  key file `gateway.key` (its QUIC client key, which the nodes list in
  `gateways`, and the key its own-key HTTPS presents); public TLS from PEM
  files or its own key; the per-address limits; the SSH port, host key
  and limits.
- **Leader-aware routing:** a request goes to the agent's leader as last
  learned (`Call`, `Credentialed`), any replica (reads), or the one node
  it is signed for (operator kinds, never redirected). On `NotLeader {
  leader: Some(c) }` or `Elsewhere { replicas }` the gateway resends the
  same frame to the upstream whose key is `c.node` (or the first replica
  it has), up to 4 times, as the client does; with no such upstream, or
  past 4, the answer goes to the HTTP client as is (421). Resending is
  safe for every kind it redirects (§3's "repeated"). `Busy` is passed
  on, not retried: the client's backoff stays the client's.
- **Per-address limits,** before any authentication or decoding:
  connections per source address (default 64), and requests a second
  per address with a burst (default 200, 400), past which HTTP answers
  429 and SSH refuses the channel; s4-server's `ServerLimits` bounds its
  connections before authentication.
- **The SSH port** hosts s4 (7.13's screens) and the **`vos-api`
  subsystem** [decided, S49]: under any key, a fresh ephemeral one
  expected; a byte-stream channel of frames (with ids). The gateway reads
  each header, answers `NotRelayed` for any kind outside the relay set
  (`Query`, `Time`) without reading its body or sending anything to a
  node, checks the limit, then relays the frame to a node under a fresh
  upstream id and maps the answer back. At most 16 requests in flight a
  channel. s4-server needs a hook for a named subsystem with a raw
  channel (`Server::subsystem(name, handler)`), added in the s4 repository
  (S40 makes s4 Claude's to change).
- **The s4 app's client key:** `app.key`, an ordinary VOS client key
  apart from `gateway.key`, with which the gateway's s4 app sends the
  claims (`claim(member)`, `claim_row`) of members with no key of their
  own; its authority is the registrar's invitations, which name the
  digests. 7.10b loads it and gives apps a node-API `Client` on it; the
  claim screens are 7.13's.
- **No authority** [decided, S41]: the node verifies every signature and
  proof and runs every ingress check. A compromised gateway can drop,
  delay or reorder requests and read what it relays; it can forge
  nothing, replay no operator request, and send a credentialed call only
  once (its binding).

## 7. The client's seam and the migration

- **The seam** is `node/host/src/client/http.rs`: beside it
  `client/api.rs`, a blocking node-API transport over `vos-api`'s client
  (the socket, or QUIC on a small smol runtime thread, as `vos-net`'s
  runner). `Http` becomes one arm of a `Transport` enum the `Client` and
  `Operator` hold. A `Target` takes `unix:/path` and `quic://host:port`
  (pinning the node's key, required) beside `http://` and `https://`.
  `Operator` signs `Operated` with an operator key over the API, and
  sends the token over HTTP while the node's HTTP exists.
- **Pinning:** over QUIC the client pins the node's key at the handshake,
  and `GET /`'s check (`NotTheNode`) stays the node-API transport's.
  Through a gateway a client pins the gateway's key or trusts its CA;
  `GET /` still answers the node's key, which it does not compare (Q5).
- **Redirects over the API** need a node's API address for a `Contact`:
  the node-API client takes them from its own table, by node key (its
  config, or `vos-scale`'s inventory); `Contact` and the space file are
  unchanged (Q5).
- **The order:**
  1. the host's tests and the checker over both transports, chosen by
     the harness, the HTTP arm through the gateway once it exists;
  2. `vosx` (`node/cli`): `--node unix:…` and `quic://…`, operator
     commands signing with `operator.key`;
  3. `vos-scale`: its drivers' pool becomes one QUIC connection a node,
     a stream a request, the driver's key listed in each node's
     `gateways` by `deploy`; `collect` signs `Stats` and `Status` with the
     harness's operator key; the gateway's cost a row of its own (S41);
  4. the end-to-end suites through the gateway.
- **The differential test** runs while both exist (§9).
- **Deleting the node's HTTP** (`ingress.rs`, `http.rs`, `tls.rs`,
  `admin.token`, the `--tls` flags, which move to the gateway) waits on
  S50: the gateway carries every route, the HTTP tests pass through it,
  and 7.6's final scale run is done, or T1 is re-measured over the node
  API and both recorded [decided].

## 8. The tests

From §7.10b's list, then this brief's additions.

| # | test | where |
|---|---|---|
| 1 | every route through the gateway answers as the node's HTTP: one corpus (each route, valid, malformed, a bad id, oversize by one, unknown paths, `Expect`, chunked) sent to two fresh nodes of one config, one by its HTTP and one through a gateway; statuses and bodies equal, `now` fields masked | gateway |
| 2 | each kind's body one past its limit refused `Oversize { limit }` from the header alone (the test sends the header and no body) | node, gateway |
| 3 | an unknown kind `UnknownKind`; a length below the header `Truncated` (id 0 on a stream); a body cut short then the write side shut, `Truncated`; each followed by the stream's or connection's close | node |
| 4 | a QUIC client with an unlisted key, and one with another ALPN, refused at the handshake | node |
| 5 | a gateway that flips a byte of a signed call's arguments: `BadSignature` from the node | gateway |
| 6 | an operator kind over QUIC `Operator(SocketOnly)` before C5 | node |
| 7 | after C5: an operator kind unsigned (`Malformed`), by an unlisted key (`Unauthorized`), with a bad signature, signed for another node (`BadSignature`), replayed (`Replayed`), and replayed after a restart, expired and too far ahead (`Expiry`), each refused, over both transports | node |
| 8 | over `vos-api`, each kind but `Query` and `Time` answered `NotRelayed`, the channel closed, and the node's count of API frames unchanged | gateway |
| 9 | the gateway following `NotLeader` and `Elsewhere`; passing 421 past 4 or for an unknown key; never redirecting an operator kind | gateway |
| 10 | the end-to-end suites through the gateway | e2e |
| 11 | out of order on the socket: a `Workflow` read waiting 2 s and a `Time` sent after it, `Time` answered first, each by its id | node |
| 12 | 256 in flight on one socket connection: the 257th read only as one ends | node |
| 13 | `Time` within a few ms of the node's clock; over `vos-api` too | node, gateway |
| 14 | the codec: pinned encodings of headers, `FrameError`, `Operated`'s message; proptests of the incremental reader against split reads; fuzz targets for the reader and `Operated`'s decode in `just fuzz` | `vos-api` |
| 15 | per-address limits: past the burst, 429 | gateway |
| 16 | `vos-scale`'s localhost inventory driving over the node API, a short run | scale |

## 9. The commits

Each one reviewable alone, `just check` green at each; days of an
implementing agent.

| | commit | days |
|---|---|---|
| C1 | `vos-api`: the codec, `Kind` and its table, `FrameError`, `Operated`; `Rejection::Operator` in `vos-wire`; test 14 | 1.5 |
| C2 | the node: `api::handle` from `Ingress::handle`; the route table and `status` moved to `vos-gateway`'s library with `http.rs` and `tls.rs`'s server half, runtime-neutral; the node's HTTP a translation onto `api::handle`; the ingress tests unchanged and green | 2 |
| C3 | the node: the unix socket, `Time`, operator kinds bare on it; tests 2, 3, 11, 12, 13 | 1.5 |
| C4 | `vos-net`'s TLS builders; the node's QUIC endpoint, `gateways`; tests 4, 6 | 2 |
| C5 | signed operator requests: `Operated` checks, `operators`, `operator.key`, the nonce store; operator kinds on both transports; test 7 | 2 |
| C6 | the client: `client/api.rs`, `Transport`, the targets, `Operator` signing; `vosx`'s flags; the checker; the host's tests over both transports | 2.5 |
| C7 | `vos-gateway`'s binary: tokio, config, HTTP onto the API, leader-following, limits, public TLS; tests 1, 5, 9, 15 | 3 |
| C8 | s4: the named-subsystem hook (its repository); the gateway's SSH port, `vos-api`, `app.key`; tests 8, 13 | 2 |
| C9 | `vos-scale` over the node API, the gateway's cost row; the end-to-end suites through the gateway; tests 10, 16 | 2 |
| C10 | (gated by S50) the node's HTTP deleted | 0.5 |

About 19 days, past the plan's 2–3 weeks by a few days. C10 lands when
S50's gate is met, which may be after the step's review. Fable reviews
this brief before C1; the Opus review takes each commit.

## 10. Open questions

1. **The `vos-api` relay set** (S49 says queries and `Time`). To sign a
   query the client needs the agent's identity, the hash of its creation
   record (`AgentInfo`), and to call by name its schema. (a) Keep S49's
   two; 7.13's client pins the identity and method ids at enrollment, as
   it pins the handle. (b) Add `NodeKey`, `AgentInfo` and `Schema`:
   public reads the node serves unsigned to any client today.
   **Recommend (b).**
2. **Operator routes over the gateway's HTTP.** Byte for byte needs the
   node's token in the gateway, which S41 forbids. (a) The routes take
   the `Operated` envelope as their body. (b) No operator routes over
   HTTP; operators use the node API (`vosx` over the socket or QUIC).
   **Recommend (a):** S50's gate asks for every route through the
   gateway, and the console of S46 relays frames anyway.
3. **The local operator key.** (a) `operator.key`, made at first start
   and listed by default, replaces `admin.token`; every operator kind is
   signed, on the socket too. (b) The socket keeps taking unsigned
   operator kinds after C5. **Recommend (a):** under (b) a co-located
   gateway would hold authority.
4. **The nonce store across restarts.** (a) Durable, in the node's
   store. (b) In memory, the node refusing operator kinds for 120 s after
   start. **Recommend (a):** cheap at operators' rates, no dead window.
5. **Addresses and pinning through a gateway.** `Contact` pairs an
   address with the key its TLS shows, which a gateway cannot show. (a)
   For 7.10b the node-API client maps contacts by key from its own table,
   HTTP clients through a gateway pin the gateway's key or a CA, and the
   space file's `ingress` column names each node's gateway. (b) A fifth
   space-file column, the API address, carried in `Contact` (a `vos_wire`
   change to `Response`). **Recommend (a)** now, (b) when clients outside
   the operator's inventory dial nodes directly.
6. **The API's QUIC endpoint.** (a) Its own UDP port and thread. (b) The
   peer endpoint, told apart by ALPN. **Recommend (a):** different
   allowlists and stream types, and API load kept off consensus's thread.
7. **`Stats` and `Status` as operator kinds** (the token gates them today;
   S46's list omits them). (a) Operator kinds, signed. (b) Any API
   client. **Recommend (a):** nothing gated today opens.
8. **s4 as a dependency.** (a) A git dependency on codeberg's `Virto/s4`
   pinned by rev, as `stwo` and `lsm-tree` are. (b) A path dependency.
   **Recommend (a)**, the hook pushed to s4 first.
9. **`FrameError::Unavailable`**, beyond the plan's four (§2). **Recommend
   adding it**; a relay otherwise has no answer for `Time` or `NodeKey`
   when its upstream fails.
10. **For 7.11, not this step:** the binding digest of
    `identity-and-authority.md` §5 and pin I says `arguments` in SCALE
    with "a compact length"; the codec has no compact encoding, and
    `arguments.encode()` writes a `u32` LE length. **Recommend** 7.11 hash
    the codec's bytes (`u32` LE length, then the bytes) and fix the text.
