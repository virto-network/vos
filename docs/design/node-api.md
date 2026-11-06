# The node API and the gateway

A node keeps one binary API: `vos_wire` request and answer frames over a
unix socket (a co-located gateway, a local tool) and over QUIC with
mutual TLS (remote gateways and drivers). Its HTTP routes, public TLS,
s4's SSH screens, limits per address and leader-aware routing across a
space's nodes live in a gateway, a separate process that holds no
authority: the node verifies every signature and proof and runs every
ingress check, whoever relays the frame [decided]. So the node carries
no HTTP parser, TLS certificate handling or SSH stack, and a compromised
front can deny service but forge nothing. It builds on
`identity-and-authority.md` §5–§6 (the credentialed call, operator
requests).

Tags as in the core model: [decided] a settled choice, [measured] by a
run. Everything here is built.

## 1. What it builds on

- **The encoding.** `vos_wire` encodes with `vos-pvm-codec`, "SCALE
  without compact encoding": integers fixed-width little-endian;
  `Vec<T>` and `String` a `u32` little-endian count, then the items;
  `[T; N]` no prefix; `Option` a byte 0 or 1, then the value; an enum a
  `u8` index (`#[codec(index = n)]`), then the variant's fields;
  `decode_exact` refuses trailing bytes. It is not parity-scale-codec's
  encoding of any type holding a vector. This doc's "SCALE" is this
  codec.
- **The peer network** (`node/net`) is QUIC (quinn, `runtime-smol`) with
  TLS 1.3 and raw ed25519 public keys (RFC 7250) on both sides, ALPN
  `vos/1`, the accepting side checking the dialer against the configured
  peers, no session resumption; unidirectional streams only, framed by a
  big-endian `u32` length, on a network thread of its own.
- **s4's server** (`s4-server`) is tokio and russh. It dispatches SSH
  subsystems by name, a named subsystem with a raw channel among them
  (`Server::subsystem(name, handler)`); authentication is pluggable
  (`authenticator_fn`), and its `Identity` is the key's fingerprint.

## 2. The frame grammar

- **A frame** [decided]:

  | field | bytes | |
  |---|---|---|
  | `length` | 4, `u32` LE | the bytes that follow it |
  | `kind` | 2, `u16` LE | §3's number; `0xffff` the frame error |
  | `mark` | 1 | the transport mark: 0 none, 1 clearnet, 2 onion (below) |
  | `id` | 8, `u64` LE | **on a byte stream only** (the socket, the `vos-api` channel) |
  | body | `length − 3` (QUIC) or `length − 11` (stream) | the kind's request or answer, in SCALE |

  The header is 7 bytes over QUIC and 15 over a byte stream. Little-endian
  throughout, as the codec, where `vos-net`'s peer frames carry a
  big-endian length: the two never meet (separate ports and ALPNs, §5). A
  `u32` length bounds a frame at 4 GiB, past every limit (the largest, an
  install, is 64 MiB plus 4 KiB plus 160).
- **An answer frame** carries the request's `kind`, or `0xffff` for a
  frame error, mark 0, and (on a stream) the request's `id`, then the
  answer's body. A request has exactly one answer frame, or none if the connection
  ends first.
- **The transport mark** [decided, `light-node.md` §3.3, E17, E22]: the
  transport a gateway received a request on, which it writes on every
  frame it relays (`vos_api::Mark`): 1, clearnet, from its HTTP and SSH
  ports; 2, onion, from its onion service's (`light-node.md` §6.1; the
  gateway's `Http.mark` and the SSH relay's mark, every port it opens
  today clearnet, the onion port with the onion service). A
  relay never passes a client's mark on: the `vos-api` subsystem relays
  each frame anew under its port's mark. Every other sender (a local
  tool on the socket, a driver, a test, the node's own client) sends 0,
  none, and the node takes none as clearnet. The node trusts the mark as
  it trusts any API client (the socket's file mode, a QUIC key in its
  `gateways`): it is the gateway's word, read only for an agent that asks
  to be onion-only (§3), defence in depth against a client's bug and
  against strangers on the clearnet. The enforcement of "anonymous calls
  never over the clearnet" is the client's routing, which has no
  clearnet route for them (`light-node.md` §6.5).
- **Ids** are the client's: the node echoes them and keeps no table, so
  an id reused while in flight gives the client two answers it cannot
  tell apart. Clients count from 1. A frame error the node cannot tie to a
  request (a length too short to hold an id) carries id 0. A relay keeps
  the only table: its own upstream ids, mapped back to the client's.
- **Read before decoding,** in this order, each failure a frame error:
  1. `length` below the header's rest (3, or 11): `Truncated`;
  2. `kind` not in the table: `UnknownKind`, `0xffff` among them (a frame
     error is an answer, never a request);
  3. on a relay, `kind` not relayable there: `NotRelayed` (§6);
  4. `mark` not 0, 1 or 2 on a request, or not 0 on an answer:
     `UnknownMark`;
  5. the body (`length` less the header's rest) past the kind's limit:
     `Oversize { limit }`, before any body byte is read or allocated;
  6. the stream or connection ending before `length` bytes:
     `Truncated` (answered if the peer still reads, else nothing).

  Then the body is decoded exactly (`decode_exact`). A body that does not
  decode is not a frame error: it is the kind's own answer, for kinds
  answering `Response` a `Rejected(Malformed)` (HTTP 400); for
  `AgentInfo` and `Schema` (answering `Option`s) `None`, as the gateway's
  empty 404 for an id that is not a `u32`.
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
      #[codec(index = 5)]
      UnknownMark,
  }
  ```
  A relay whose upstream fails mid-request must answer every kind, and
  three kinds answer types with no `Unavailable` of their own (`NodeKey`,
  `Time`, the `Option`s), hence the frame error's `Unavailable`. A node
  answers the `Response` kinds' own `Unavailable` instead.
- **Close:** after one of the five framing errors (`Oversize`,
  `UnknownKind`, `Truncated`, `NotRelayed`, `UnknownMark`) the node (or
  relay) writes it, then closes the QUIC stream (finishes its side and stops reading), or
  the whole connection on a byte stream, whose framing it may no longer
  trust: answers in flight on that connection are dropped. A well-behaved
  client never meets one. **`Unavailable` does not close:** the framing is
  intact, so it is answered under its id and the channel goes on, its
  other requests in flight with it (a device's path refresh shares a
  `vos-api` channel).
- **Order:** over QUIC, one request per bidirectional stream: the client
  writes one frame and finishes; the node answers one frame and finishes.
  Over a byte stream, the node reads frames in order and starts each as
  it arrives, answering each when it is done, out of order; it writes an
  answer frame whole, never interleaved with another. No order holds
  between two requests in flight: a client that needs one (a session's
  calls, by sequence) waits for the first answer. Reading in order means a
  frame that trickles in stalls the frames behind it on that connection
  for up to its deadline: a byte stream is the co-located gateway's, or a
  local tool's, which stalls only itself.
- **Deadlines:** a frame must arrive within 60 s of its first byte, on
  every transport and on the `vos-api` channel; a QUIC connection idle
  30 s closes; a socket connection has no idle limit (local, file-mode
  access).
- **The client's side:** an answer body past 16 MiB (`MAX_ANSWER`) is
  refused before it is read, and the connection closed.

## 3. The kinds

Bodies and answers in SCALE. `Agent` is `AgentId`, a `u32`. "HTTP" is the
gateway's route. **Limit** is the body's, in bytes, checked from the
header. Ranges group the senders: `0x00xx` unsigned reads, `0x01xx` a
client's signed requests, `0x02xx` operator requests; the table, not the
range, is the rule.

| kind | name | HTTP | body | answer | limit |
|---|---|---|---|---|---|
| `0x0001` | `NodeKey` | `GET /` | empty | `NodeId` | 0 |
| `0x0002` | `Time` | `GET /time` | empty | `u64`, ms by the node's clock | 0 |
| `0x0003` | `AgentInfo` | `GET /agents/{a}` | `Agent` | `Option<AgentInfo>` | 4 |
| `0x0004` | `Schema` | `GET /agents/{a}/instances/{i}/schema` | `(Agent, InstanceId)` | `Option<Schema>` | 8 |
| `0x0005` | `Devices` | `GET /agents/{a}/instances/{i}/devices` | `(Agent, InstanceId)` | `Option<DeviceWindow>` | 8 |
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
| `0x0209` | `Retire` | `POST /retire` | `Operated` of `Retire` | `Response` | 69,792 |

`0x0000` is never assigned; a kind's number never changes or returns.
`0xffff` is the frame error's, an answer only: as a request it is
`UnknownKind`. `0x0104`, the credentialed call: its checks, in order, are
`identity-and-authority.md` §5's (and `node/SECURITY.md`'s); its body is
large (every proof is past a call's limit), and takes one of 64 places of
the credentialed calls' own, apart from the installs': the body is
dropped once decoded and the place given back once the proof is
verified, so the places bound proofs held and verified, not calls waiting
to apply; its verifications are bounded by the node's verification
budget, past which it is answered `Busy`.

- **Who may send each, and what may be repeated:**

  | kind | sender | over `vos-api` | repeated |
  |---|---|---|---|
  | `NodeKey`, `AgentInfo`, `Schema`, `Devices` | any API client | relayed | yes: reads |
  | `Time` | any | relayed | yes |
  | `Query` | any; its key signs it | relayed | yes: a read |
  | `Workflow` | any; the workflow's owner signs it | no | yes: a read |
  | `Call` | any; its session's key signs it | no | yes: the session's sequence dedupes |
  | `Credentialed` | any; its proof is its authority | no (the demo's device sends it over the gateway's s4 facility) | yes: a repeat is answered `Replayed`, not the first outcome |
  | `Stats`, `Status` | an operator key, signed (§4) | no | yes: reads, signed with an expiry, no nonce recorded |
  | the other `0x02xx` | an operator key, signed (§4) | no | no: each nonce once |

  "Any API client" is anyone holding the socket's file mode, or a QUIC
  key in the node's `gateways` (§5). `Stats` and `Status` are operator
  kinds: the node shows them to its operators only.
- **The limits** are the HTTP routes' limits plus the API's fixed
  additions, so a body the gateway's route takes always fits its kind and
  the gateway never turns a 200 into a 413 or back: `Call`, `Query`,
  `Workflow` the HTTP body's 69,632 (`cap::REQUEST` plus a 4 KiB
  envelope) plus 4 for the agent; an operator kind its HTTP limit
  (69,632, or 67,112,960 for an install: `MAX_ELF` plus 4 KiB) plus 4 for
  the agent where it names one, plus `Operated`'s 156 bytes (node 32,
  key 32, nonce 16, expiry 8, the inner body's length 4, signature 64),
  rounded up to the same figure for every operator kind but the install
  and the two reads; `Stats` and `Status` 4 KiB plus 156. `Credentialed`
  is a device proof's 1.5 MiB budget plus `cap::REQUEST` plus 4 KiB (the
  agent inside the 4 KiB); the gateway's HTTP limit for it is 4 less.
  `MAX_ELF` lives in `vos-wire` (`vos_wire::abi::cap::MAX_ELF`), so the
  API's table pulls no compiler into the gateway or a client.
- **Answers are the HTTP bodies,** so the gateway passes them through:
  `NodeKey` the 32 bytes of `GET /`; `AgentInfo`, `Schema` and
  `Devices` as `Option`s, `None` for the gateway's empty 404 (the gateway strips the
  tag byte and sends the rest, never re-encoding); `Response` with its
  HTTP status from one `status` function (§6).
- **An empty inner body** of `CreateAgent` or `CreateRepresentative` is
  `Create::default()`, as an empty `POST` body is.
- **`Time`** answers the node's clock (`Inner::clock`, wall time in ms),
  unsigned: a relay that lies about it costs a client a new proof
  (`identity-and-authority.md` §5).
- **`Devices`** (`light-node.md` §4.4): an installed instance's device
  window as this node holds it: the device formats it admits now, newest
  first, each with its retirement if one is set, and for each device
  kernel the programs its guard admits, newest first (its release's, and
  its previous release's until that retires), each its id, its format and
  its date. The node computes a program the first time a read or a proof
  names it, on an executor, once a release; a kernel's window it could
  not compute whole yet (a blob it does not hold) says `unavailable`. A light node reads it before
  it proves, and proves with the newest program it ships that the window
  holds. An onion-only agent's window is read through the onion alone,
  as its schema is.
- **`Retire`** (`light-node.md` §4.4): `Previous { agent, instance,
  method, at_ms }` sets device kernel `method`'s previous release's
  retirement to `at_ms` if that is earlier (now included), through the
  agent's log (`Admin::Retire`, its outcome the date kept); `Format {
  format, at_ms }` sets device format `format`'s at the node that takes
  it, until it restarts (`Config::retired_formats` keeps one across
  restarts), its outcome the date kept, `Malformed` for a format the node
  does not verify. Neither ever moves a date later.
- **The credential actor's `path(member)` and `root()`** are `Query`s
  like any other, signed by a key the device library draws for each
  (`identity-and-authority.md` §6); no kind of their own.
- **An agent's admission** [decided, `light-node.md` §3.3]: an actor
  declares it, `#[actor(known_keys, onion_only)]`, and its schema carries
  it (`vos_wire::schema::Admission`, after the credentials' part of the
  section); its install writes the agent's row `admission`
  (`vos_wire::keys::admission`: the declaring instance and the two flags),
  which ingress reads as it reads the credential ring. One actor of an
  agent declares it: an install declaring one at another instance, or
  installing a program that declares none over the declaring instance,
  fails `Admission` (16). Ingress checks it before any signature or
  proof, reading this replica's applied state:
  - **onion only:** a `Call`, `Query`, `Workflow` or `Credentialed` whose
    frame is not marked onion is refused `Admission(OnionOnly)`, and a
    `Schema` or `Devices` read of the agent answered `None`. `AgentInfo` (the
    directory's record and replicas, no read of the agent's state) and
    the node's kinds stay open.
  - **known keys only:** a `Call` whose session the agent does not hold
    (its row `session_index` absent) is refused `Admission(UnknownKey)`
    unless its session's key is a row of the declaring actor's hashed
    table `admitted` (`vos_wire::keys::admitted`; any value, its presence
    read). So an unknown key costs three point reads (the agent's row
    `admission`, the session's, the key's), no verification and no write:
    10^4 session attempts verified nothing and wrote nothing (§8, test
    18). A call in a session the agent holds is not looked up: admission
    covers the creation of sessions; a key no longer admitted keeps its
    sessions until they expire, and the actor's handlers judge the rest.
    A key admitted in the latest batch may be refused at a replica that
    has not applied it; the client retries. Queries and workflow reads
    are signed by any key and not looked up: the actor's handlers gate
    them. A credentialed call has no key: its guard admits it.

  Apply does not check either: the rows are ingress's filter, so a call
  forwarded between replicas was checked at the replica that took it.
- **`Rejection` variants** (`vos_wire::ingress`): index 9 is
  `Credential(CredentialRefusal)` (`identity-and-authority.md` §5);
  index 10 is `Operator(OperatorRefusal)`:

  | index | `OperatorRefusal` | HTTP |
  |---|---|---|
  | 0 | `Expiry { now }`: `expires_ms` outside `now ..= now + 120 s`, or at or below the floor (§4) | 403, as `Credential(Expiry)` |
  | 1 | `Replayed`: the `(key, nonce)` of a write kind recorded | 409 |
  | 2 | `OtherNode`: the envelope names another node | 421 |

  An unlisted key keeps `Unauthorized` (6, 401), a bad signature
  `BadSignature` (0, 401); a body that is not an `Operated` is
  `Malformed`. Index 11 is `Admission(AdmissionRefusal)`: 0 `OnionOnly`,
  1 `UnknownKey`, both 403.

## 4. Operator requests

[decided]: each operator kind is signed by an operator key the node's
config lists, with a nonce and an expiry, as a call is signed; the node
keeps each nonce until its expiry. So no front holds a bearer secret it
could replay, and a relay keeps nothing it can reuse.

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
  `"vos/operator/v1" ‖ node ‖ kind ‖ nonce ‖ expires_ms ‖ body`: `node`
  the addressed node's `NodeId` (32 bytes), `kind` 2 bytes LE,
  `expires_ms` 8 LE, `body` as SCALE (a `u32` LE length, then the bytes),
  in `vos_wire::ingress`'s `message` form (domain, then an identity, then
  the fields). A request is good at one node for one kind: a relay cannot
  send it to another, and a node's own nonce store is enough. The
  envelope names its node so a relay can route it to the one node it is
  signed for, and that node refuses it as `Operator(OtherNode)` before
  any signature check.
- **The node's checks, in order:** the frame; the envelope's fixed
  88-byte prefix present (`Malformed`); `node` is this node
  (`Operator(OtherNode)`); `key` listed (`Unauthorized`);
  `now ≤ expires_ms ≤ now + 120 s` and above the floor
  (`Operator(Expiry { now })`); then, off the node's thread as
  `Ingress::signed` does, the envelope decoded (`Malformed`) and its
  signature checked (`BadSignature`), so a body as large as an install is
  copied only for a listed key's request to this node in time; for a
  write kind, the nonce looked up (`Operator(Replayed)`) before the inner
  body is parsed; the inner body decodes (`Malformed`); for a write kind,
  the nonce recorded (below); then the command runs. The signature comes
  before the store, so junk fills nothing.
- **Recording a nonce** is one step on the node's thread, after the
  signature returns: an insert of `(key, nonce)` if absent
  (`Operator(Replayed)` if present), so two copies of one request in
  flight on the multiplexed socket cannot both pass; then the row is
  written and synced (`fsync`) before the command runs, so a request
  whose command ran is refused after a restart (`Unavailable` if the
  write fails, the command not run). The reads (`Stats`, `Status`) record
  none: a replayed read within 120 s discloses nothing the first did not,
  to a holder of the first, and `vos-scale`'s collector polls `Status` of
  every placed agent each interval, past any bound at 10^4 agents.
- **The nonce store:** a node-local table in the node's store (fjall, not
  replicated), `key ‖ nonce → expires_ms`, loaded at start, swept as
  entries expire. Durable, so a restart replays nothing. An entry is
  forgotten only once the node's clock is past its expiry by more than
  the 120 s horizon, so a clock stepped back by up to the horizon still
  refuses the replay. **The floor**, the latest expiry of a nonce
  forgotten, is stored (`NodeRow::OperatorFloor`): a command expiring at
  or below it is refused `Expiry`, so a clock stepped back past the
  horizon refuses a forgotten nonce's replay too; a clock that ran ahead
  is warned of at start (`docs/operations.md`). At most 65,536 live
  entries; past them, `Busy`. The listed keys are the node's operators,
  all trusted alike: the bound is shared, not per key.
- **The keys,** in the node's TOML (`node/cli/src/config.rs`):
  `operators = ["<hex>", …]`. The node also makes `operator.key` in its
  data directory at its first start (mode 0600) with `operator.pub`
  beside it, and lists that public key unless `local_operator = false`,
  so the CLI on the node's host signs as an operator; after the first
  start the node reads only `operator.pub`. The client's `Operator`
  learns the node's time from `Expiry { now }`, as `with_learned_time`
  does for queries, and signs again once, with the same nonce: a relay
  that holds the first copy back and forges the refusal gets the command
  run once between the two, never twice. A signed command may go again on
  a fresh connection, its nonce deduping it: if the first copy ran before
  the kept connection failed, the resend answers `Replayed` (409), not
  the command's outcome, which the operator reads from the node.
- **Every transport, the socket included:** an unsigned operator body is
  refused everywhere, since a co-located gateway on the socket must hold
  no authority either; `api::handle` takes no transport argument, only
  the frame's mark, which no operator kind reads.
- **The gateway and s4's console only relay:** they carry an `Operated`
  the operator built in their own client; nothing they keep can be
  replayed past its nonce, sent to another node, or outlive its expiry.

## 5. The transports

- **The unix socket** [decided]: `api_socket` in the node's config, by
  default `<data>/api.sock`, made at start with mode `api_socket_mode`
  (default 0660: the node's user and group). A lock file beside it
  (`api.sock.lock`, an exclusive `flock` held for the node's life) decides
  between twins: the node that holds it removes a stale socket file and
  binds; one that cannot take it refuses to start. The file mode is the
  access; no peer credentials are read. Byte-stream frames with ids,
  multiplexed (§2).
- **QUIC with mutual TLS** [decided]: a second QUIC endpoint on its own
  UDP port (`api_listen`), apart from the peer endpoint: its own
  allowlist, bidirectional streams (the peers' have none), and a thread
  of its own, so API load never shares the consensus network's. TLS 1.3,
  raw ed25519 keys both ways, the node's own key as the server's, ALPN
  `vos-api/1`; the client's key checked at the handshake against
  `gateways = ["<hex>", …]` in the node's config, an unlisted key or
  another ALPN refused there; no resumption, no tickets, as the peers'.
  `vos-net` exposes its TLS builders (the ALPN and the allowlist as
  parameters) and its executor, the runner quinn's runtime needs
  (`vos_net::api`); the endpoint itself lives in the node
  (`node/host/src/api/`). The gateway enables quinn's `runtime-tokio`
  beside `vos-net`'s `runtime-smol`: each endpoint names its runtime
  explicitly, so the unified features change nothing in the node. A
  `gateways` key is a transport admission, no authority: a driver of
  `vos-scale` or a remote `vos` is listed the same way.
- **Limits:** `api_connections` connections per transport (default
  1,024), more refused at accept (the socket) or the handshake (QUIC);
  `api_in_flight` requests in flight per connection on both transports
  (default 1,024), past which the node stops reading the socket, and
  QUIC's `max_concurrent_bidi_streams` (set to it) holds the client back.
  At 5,000 calls a second and a 50 ms p99 about 250 are in flight, so one
  connection never caps a co-located gateway or a driver below the node's
  own; the gateway still keeps a few socket connections a node. The
  verification budget (`Busy`) is per node. Over QUIC a client proves its
  address first (a Retry), at most 64 handshakes are under way, 8 from one
  address (an IPv6 /64), each within 10 s, and `api_connections` counts
  connections that shook hands. A host that passed Retry needs no key to
  hold a handshake's place until the TLS verdict, so the API's port is
  for gateways and drivers: a deployment firewalls `api_listen` to them.
  At most four large bodies (an install's, past `vos_api::LARGE`) are held
  at once across the socket and QUIC: the socket reads a large frame's
  body only once it holds a place, its deadline running from then, and
  QUIC answers `Unavailable` from the header. A frame's deadline runs from
  its own first byte on a byte stream, and from the stream's accept on
  QUIC. After a frame error on the socket, the requests in flight run on
  detached while the connection's place is given back, so a local client
  can have more running than `api_connections × api_in_flight`; the
  socket's mode bounds who can. Queries waiting for their replica to reach
  their floor are at most `floor_waits` (256): one past them is answered
  `Behind` at once, so slow reads cannot hold a connection's in-flight
  places for long.
- **One handler:** `api::handle(kind, body) → answer bytes`, which both
  transports call; the gateway's HTTP is a translation onto it (§6). The
  differential corpus that compared it with the node's former HTTP
  ingress is pinned to what both answered.

## 6. The gateway

- **Layout:** three crates, the node depending on none that pulls tokio,
  russh or s4.
  - `vos-api` (`node/api`): the frame codec (sans-IO: a header type, an
    incremental reader, the writer), `Kind` with its limits, senders and
    relay set, `FrameError`, `Operated` and its message; a client of the
    node API over a byte stream (multiplexed) and over QUIC (a stream a
    request), generic over futures-io, the QUIC side over quinn's own
    API whatever its runtime. The node, the gateway, the client and s4's
    client facility share it. The multiplexed client only queues a whole
    frame; its task writes it, so a request cancelled at any point leaves
    no part of a frame on a stream others share.
  - `vos-http` (`node/http`): the HTTP/1.1 server (runtime-neutral: an
    accept stream and a spawn function), the public TLS, and the route
    table (path parsing, `status`, the operator header, the answer's HTTP
    form). The gateway imports it; so does the node's client, for HTTP to
    a gateway. The node serves no HTTP.
  - `vos-gateway` (`node/gateway`), a library and the binary
    `vos-gateway`, depending on `vos-api`, `vos-http`, `vos-wire`,
    `vos-net`'s TLS builders and `s4-server`, never on the node.
- **Runtime:** tokio. s4-server is tokio and russh and installs no
  runtime; the binary builds a multi-threaded tokio runtime, serves HTTP
  through `tokio_util::compat` over the runtime-neutral server, and dials
  nodes with quinn's tokio runtime. One runtime, no bridge; the codec is
  sans-IO, so the smol node and the tokio gateway share it.
- **HTTP:** `Content-Length` bodies only, keep-alive, 16 KiB heads, 30 s
  idle, 60 s a request, plain on loopback or TLS 1.3 (a certificate for
  the gateway's key, which clients pin, or PEM files). Paths, bodies and
  statuses by the route table: `GET` bodies read and counted against the
  limit, then unused; an empty `POST /agents` or `/representative` body
  as `Create::default()`; an id that is not a `u32` answered with an
  encoded `NoAgent` and 404 on the request routes, an empty 404 on
  `GET /agents/{a}` and the schema; unknown paths an empty 404; 411 on
  chunked bodies, 413 past a limit (the install's by the path's suffix,
  even on an unknown path), 431 past a 16 KiB head or too many header
  lines, `100 Continue` honoured.
- **Large bodies:** `vos-http` holds at most four bodies past its
  ordinary limit (an install's) at once, from every connection
  (`Limits::large`), and answers a request past them 503 from its head,
  the body unread. Before that, the gateway answers an operator's route
  from its head, as the whole request would be answered: 401 with no
  `Operated` header (or one that is not 152 bytes), 421
  `Operator(OtherNode)` for an envelope naming no upstream. Neither
  answer depends on the body, and a request with no plausible envelope
  never reaches the budget. A refused body past the ordinary limit, or
  one the client waits for `100 Continue` to send, is never read: the
  connection closes after the answer.
- **The operator routes:** a bearer token at the gateway would be
  authority it holds, so the routes keep their methods, paths and bodies,
  and the envelope's fields ride in the header:

  `Authorization: Operated <base64 of node ‖ key ‖ nonce ‖ expires_ms ‖ signature>`

  (152 bytes, `expires_ms` 8 LE, standard base64 with padding). The
  gateway composes the frame's `Operated` from them, its inner body
  `agent ‖ body` for a route naming an agent (`Status`'s inner body the
  agent alone), the body alone for `POST /agents` and `/representative`,
  empty for `GET /stats`; the operator's client signs the same bytes. So
  the path's agent is the signed one, and `Stats` and `Status` keep their
  empty `GET`s. A path whose id is not a `u32` is answered with an
  encoded `NoAgent` (404) before any frame: the gateway cannot form one.
  A missing or unreadable header, a bearer token among them, is
  `Rejected(Unauthorized)`, 401.
- **Its configuration** (a TOML file): the upstream nodes, each by its key
  and API address (`quic://host:port`, or `unix:/path` for a co-located
  one); its key file `gateway.key` (its QUIC client key, which the nodes
  list in `gateways`, and the key its own-key HTTPS presents); the HTTP
  listener and public TLS from PEM files or its own key; the per-address
  limits; the SSH port, host key and limits; `app.key`.
- **Leader-aware routing:** a request goes to the agent's leader as last
  learned (`Call`, `Credentialed`), any upstream (reads), or the one node
  it is signed for (operator kinds, by the envelope's `node`, never
  redirected; an envelope naming no upstream is answered
  `Operator(OtherNode)` by the gateway, 421). On
  `NotLeader { leader: Some(c) }` or `Elsewhere { replicas }` the gateway
  resends the same frame to the upstream whose key is `c.node` (or the
  first replica it has), up to 4 times, as the client does; with no such
  upstream, or past 4, the answer goes to the HTTP client as is (421).
  Resending is safe for every kind it redirects (§3's "repeated"). `Busy`
  is passed on, not retried: the client's backoff stays the client's. An
  upstream that fails mid-request is answered `Unavailable` (503), never
  resent. A dial holds no lock a request with a connection open waits on,
  and one dial is under way at a time per upstream; an upstream whose
  dial failed is down for a backoff (1 s, doubling to 8 s), answered
  `Unavailable` at once while it lasts, and reads in turn, and calls to a
  learned leader, skip an upstream that is down or whose dial has been
  under way for over 250 ms while another is ready: one dead node delays
  only the requests that must go to it.
- **Per-address limits,** before any authentication or decoding:
  connections per source address (default 64), and requests a second per
  address with a burst (default 200, 400), past which HTTP answers 429
  from the request's head, its body unread, and SSH refuses the channel;
  s4-server's `ServerLimits` bounds its connections and handshakes before
  authentication. s4's per-identity session caps mean nothing under
  ephemeral keys: the per-address limits are the bound.
- **The SSH port** (the `ssh` feature, off by default) hosts s4's screens
  and the **`vos-api` subsystem** [decided]: under any key, a fresh
  ephemeral one expected, the gateway's authenticator taking any public
  key; a byte-stream channel of frames (with ids). It gives a device
  paths, roots and the node's time on a connection apart from the one
  that carries its proofs, under a key that links to nothing. The gateway
  reads each header, answers `NotRelayed` for any kind outside the relay
  set (`NodeKey`, `Time`, `AgentInfo`, `Schema`, `Devices`, `Query`) without reading
  its body or sending anything to a node, checks the limit, then relays
  the frame to a node under a fresh upstream id and its port's mark (§2),
  and maps the answer back.
  The relay set is the public, unsigned or self-signed reads: an
  anonymous relay lying about `AgentInfo` costs a `BadSignature` and
  nothing more. At most 16 requests in flight a channel, past which it
  stops reading; each frame within 60 s of its first byte. A channel
  holds a place among its address's connections, as an HTTP connection
  does; each frame takes a token of its address's rate (past it, the
  channel closes) and, while in flight, a place among its address's (past
  them, it is answered `Unavailable`). An IPv6 address counts by its /64.
  The subsystem runs under s4's rule for channel input: the SSH loop's
  `data` callback never awaits, its queue `try_send`s and closes the
  connection when full.
- **The s4 app's client key:** `app.key`, an ordinary VOS client key
  apart from `gateway.key`, with which the gateway's s4 app sends the
  claims (`claim(member)`, `claim_row`) of members with no key of their
  own; its authority is the registrar's invitations, which name the
  digests. Its calls run in one session per agent, so the app sends one
  claim at a time to an agent, in order.
- **s4 as a dependency:** a git dependency on codeberg's `Virto/s4`,
  pinned by rev from its `vos` branch, behind the gateway's `ssh`
  feature; s4's crates ask a newer stable Rust than the workspace's
  nightly names, which builds them with `--ignore-rust-version`
  (`just test-gateway-ssh`).
- **No authority** [decided]: the node verifies every signature and
  proof and runs every ingress check. A compromised gateway can drop,
  delay or reorder requests and read what it relays; it can forge
  nothing, replay no operator request, and send a credentialed call only
  once (its binding).

## 7. The client

- **The transports:** `node/host/src/client/` holds a blocking node-API
  transport over `vos-api`'s codec (`client/api.rs`: the socket, or QUIC
  through quinn's smol runtime) and an HTTP one for a gateway
  (`client/http.rs`), arms of a `Transport` enum the `Client` and
  `Operator` hold. A `Target` takes `unix:/path` and `quic://host:port`
  (pinning the node's key, required) beside `http://` and `https://`.
  `Operator` signs `Operated` with an operator key: over the API as the
  body, over HTTP in the `Authorization` header.
- **Pinning:** over QUIC the client pins the node's key at the handshake,
  and `GET /`'s check (`NotTheNode`) stays the node-API transport's.
  Through a gateway a client trusts the gateway: `Trust::Gateway(key)`
  pins the gateway's own-key TLS (or `Trust::Ca` its CA's), keeps that pin
  across redirects, and skips `NotTheNode`, since `GET /` still answers a
  node's key. A node's key pins QUIC only: `https` with `Trust::NodeKey`
  is refused. Every node's `contact` column in the space file names its
  gateway, so a redirect through a gateway converges on the gateway,
  which routes again.
- **Redirects over the API** need a node's API address for a `Contact`:
  the node-API client takes them from its own table, by node key (its
  config, or `vos-scale`'s inventory); `Contact` and the space file are
  unchanged.
- **Who uses which:** the host's tests and the checker run over both
  transports, chosen by the harness, the HTTP arm through a gateway;
  `vos` (`node/cli`) takes `--node unix:…` and `quic://…`, operator
  commands signing with `operator.key`; `vos-scale`'s drivers keep one
  QUIC connection a node, a stream a request, the driver's key listed in
  each node's `gateways` by `deploy`, and `collect` signs `Stats` and
  `Status` with the harness's operator key; the end-to-end suites run
  through the gateway.

## 8. The tests

| # | test | where |
|---|---|---|
| 1 | every route through the gateway: one corpus (each route, valid, malformed, a bad id, oversize by one, unknown paths, `Expect`, chunked; the operator routes with an `Operated` header, a bad one, none), its statuses and bodies pinned | gateway |
| 2 | each kind's body one past its limit refused `Oversize { limit }` from the header alone (the test sends the header and no body) | node, gateway |
| 3 | an unknown kind, `0xffff` among them, `UnknownKind`; a length below the header `Truncated` (id 0 on a stream); a body cut short then the write side shut, `Truncated`; each followed by the stream's or connection's close | node |
| 4 | a QUIC client with an unlisted key, and one with another ALPN, refused at the handshake | node |
| 5 | a gateway that flips a byte of a signed call's arguments: `BadSignature` from the node | gateway |
| 6 | an operator kind unsigned (`Malformed`), by an unlisted key (`Unauthorized`), with a bad signature (`BadSignature`), signed for another node (`OtherNode`), replayed (`Replayed`), two copies at once (one runs), replayed after a restart, expired, too far ahead and below the floor (`Expiry`), each refused, over both transports; a read replayed answered; the store's bound answering `Busy` | node |
| 7 | over `vos-api`, each kind outside the relay set answered `NotRelayed`, the channel closed, and the node's count of API frames unchanged; an upstream gone answered `Unavailable` with the channel kept; 16 in flight on one channel | gateway |
| 8 | the gateway following `NotLeader` and `Elsewhere`; passing 421 past 4 or for an unknown key; never redirecting an operator kind; the HTTP client pinning the gateway and following a 421 through it | gateway |
| 9 | the end-to-end suites through the gateway | e2e |
| 10 | out of order on the socket: a `Workflow` read waiting 2 s and a `Time` sent after it, `Time` answered first, each by its id | node |
| 11 | `api_in_flight` on one socket connection: the next read only as one ends | node |
| 12 | `Time` within a few ms of the node's clock; over `vos-api` too | node, gateway |
| 13 | the codec: pinned encodings of headers, `FrameError`, `Operated`'s message; proptests of the incremental reader against split reads; fuzz targets for the reader and `Operated`'s decode in `just fuzz` | `vos-api` |
| 14 | per-address limits: past the burst, 429 | gateway |
| 15 | `vos-scale`'s localhost inventory driving over the node API, a short run | scale |
| 16 | `api_connections` refused at accept (the socket) and at the handshake (QUIC); the 60 s frame deadline on both; a stale socket file replaced, and a twin refused by the lock | node |
| 17 | the gateway's 413 never reaching the node (its count of API frames unchanged) | gateway |
| 18 | an agent's admission: an unknown key's 10^4 session attempts, each a session of its own with no valid signature, all `UnknownKey`, the node's verifications and the agent's applied index unchanged; a key admitted by another agent's message refused until applied, then its session created; a key revoked keeping its session and creating no other; every kind that reads an onion-only agent refused unmarked and clearnet, over the socket and QUIC, before any verification; the installs that would leave no declaring actor failing `Admission` | node |
| 19 | the mark on the relay path: an HTTP port marking clearnet and one marking onion in front of the onion-only agent, the clearnet's call `OnionOnly`, the onion's `UnknownKey` then run; the `vos-api` subsystem relaying an onion-marked query under its clearnet port's mark (`OnionOnly`) and under an onion port's (answered) | gateway |
| 20 | the codec: the mark pinned, each read back, an unknown one `UnknownMark` from the header; the fuzz target's frames written again being the bytes read | `vos-api` |

## 9. Design choices

- **One binary API, no HTTP in the node:** the node's surface is one
  handler behind two transports, the socket for a co-located front and
  QUIC with mutual TLS for remote ones; everything a public front needs
  (HTTP, public TLS, SSH, per-address limits, routing across nodes) is
  the gateway's, which holds no authority.
- **Signed operator requests, no token:** a token at a front is authority
  the front holds; an envelope signed for one node, one kind, one nonce
  and a 120 s expiry can be relayed and never reused. The nonce store is
  durable and synced before the command runs, so a restart opens no
  replay; reads take an expiry but no nonce, since a replayed read shows
  its holder nothing new.
- **A local operator key:** `operator.key`, made at first start and
  listed by default, so the CLI on the node's host is an operator without
  configuration.
- **The API's own QUIC endpoint:** its own port, allowlist and thread, so
  API load never shares the consensus network's.
- **`vos-api` relays public reads only:** `NodeKey`, `Time`,
  `AgentInfo`, `Schema`, `Devices` and `Query`, what a device needs beside its
  proofs; anything that changes state goes through a signed or proven
  request on another path.
- **`FrameError::Unavailable` keeps the channel:** an upstream failure is
  no framing error, so the other requests on a shared channel go on.
- **The binding digest's `arguments`** are hashed as the codec writes
  them, a `u32` LE length then the bytes (`identity-and-authority.md` §5,
  `proving.md` §8).
- **The node never depends on tokio, russh or s4:** `vos-api` is sans-IO
  and shared; `vos-http` and s4 are the gateway's.
