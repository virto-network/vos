# The node's credential surface: security considerations

What a node takes on when it serves credentialed calls, calls whose
authority is a device kernel's proof rather than a client's signature: what
ingress verifies and in what order, what the log keeps, what the operators
and the gateways that relay requests learn, and where the node is open to
denial of service. It is descriptive, not a formal argument. The design is
`docs/design/identity-and-authority.md` (§5 the request, its checks and
the apply rule; §6 the credential actor; §7 the threat model) and
`docs/design/proving.md` §8 (the statements). What the device library
holds is `node/light/SECURITY.md`'s, and what a verified proof proves is
`pvm/proof/SECURITY.md`'s.

## Who is trusted

- **A space trusts its nodes.** Ingress verifies the proof and logs only
  the origin it proved and the claim, never the proof:
  `Anonymous { scope, nullifier }` for the stock auth kernel,
  `Owner(digest)` for the stock owner kernel, `Kernel { program }` for an
  actor's own kernel. Every replica applies the origin as logged; none
  verifies again. An operator
  can therefore log an origin it never verified, as it could run any call:
  members trust their space's nodes for integrity. A space that wants
  evidence keeps the proofs in the non-repudiation side store (not built).
  Likewise a replica forwards a verified call to the agent's leader with
  its origin alone, and the leader takes it as a replica's word.
- **A group hears only its agent's placement.** A Raft message reaches an
  agent's group only from a node the placement names (and, while it is
  uncommitted, the configuration before), as forwards and blob requests
  do. The placement is what the directory spreads, which any node of the
  space can announce: the check keeps a misconfigured or removed node out
  of a group, not a node of the space that lies, which can announce a
  placement of its own. Inside the group Raft tolerates crashes, not lies:
  a replica of it that lies can break the group's safety
  (`support/vos-raft/README.md`, "Limits").
- **A gateway holds no authority.** It translates
  `POST /agents/{agent}/credentialed` and `GET /time` onto the node API
  and runs none of the checks: every check is the node's, whoever relays
  the frame. A compromised gateway can drop, delay or reorder requests and
  read what it relays; it can forge nothing. The node serves no HTTP of
  its own: its binary API alone, on a unix socket whose file mode is the
  access and over QUIC to the client keys it lists in `gateways`, a
  transport's admission and no authority. Its operator commands are
  signed by a key it lists in `operators`, each for that node, with a
  nonce and an expiry; no bearer token admits one. This holds of
  `vos-gateway`, a process apart from the node; the SSH demo's binary
  (`node/gateway/demo`) runs a node, its gateway and its operator in one
  process, so there the gateway's process holds the node's keys and the
  operator's: the demo's arrangement, not a deployment's.
- **The node's clock** (`Time`) is unsigned. A relay that lies about it
  makes the client pick an expiry the node refuses, which costs a new
  proof; it cannot extend a proof's life, since ingress judges the expiry
  by its own clock, at most 120 s ahead.

## What ingress checks, in order

A proven call carries its kernel's claim (the kernel's public arguments,
SCALE-encoded, the call's binding its last 32 bytes, at most 1 KiB) and
one device proof (format 47, or another device format the node admits:
the release admits 47 alone) of the kernel's run stating it. Each check
is cheaper than the next; every one but the last reads the request and
this replica's applied state alone. A refusal is
`Rejected(Credential(code))`, the codes in this order (the node API's
frame checks and the agent's placement come first, as for any call):

1. the frame within its kind's size (1,642,496 bytes), from its header,
   before a byte of the body is read; at a gateway's HTTP from the
   request's head;
2. the body decodes exactly;
3. this node serves the agent;
4. the agent's space has a genesis (`NoSpace`): a binding names its
   `SpaceId`, and no proof may bind `NONE`;
5. the format is a device format this node admits now, 47 by default,
   each until its retirement (`Format`);
6. the proof within the format's cap (1.5 MiB), the claim within
   `cap::CLAIM` (1 KiB), the arguments within `cap::REQUEST` less it
   (`Size`);
7. `now ≤ expires_ms ≤ now + 120 s` by the node's clock (`Expiry`);
8. the method exists and carries a guard (`Method`): `auth` or `owner`,
   the stock kernels, or one of the actor's own device kernels;
9. the claim's shape is the guard's (`Kind`): a stock auth claim's 128
   bytes (root, scope, nullifier, binding), a stock owner claim's 64
   (owner, binding), an actor kernel's at least the binding's 32; and the
   kernel's window is installed: the credential actor's for a stock
   kernel, the method's actor's for its own;
10. the window's programs are held (`Unavailable` while one is computed,
    below), at least one computed (`Kind`);
11. for auth, the scope is the one the guard's name gives in this space,
    agent and instance (`Scope`);
12. the binding is this request's under one of the window's programs
    (`Binding`): its space, agent, instance, method, program, arguments,
    nonce and expiry;
13. the binding digest is not recorded (`Replayed`);
14. for a `once` auth guard, the nullifier is not admitted in its scope
    (`Once`), before the proof: anyone who
    holds a scope's nullifier, the log's readers among them, learns
    whether it was admitted by a request bound to its own arguments and
    a proof of nothing. Checking it after the proof would spend a
    verification on every such probe;
15. for auth, the root is in the credential actor's ring (`RootUnknown`,
    retryable: an honest member meets it on a lagging replica, after a
    later write at the same batch time replaced its root (a leader whose
    clock trails times each batch a millisecond past the one before, so
    that is one batch's, or one millisecond's), or once 64 later roots
    pushed it out; it reads the tree's feed again or asks another
    replica);
16. for auth, the root is the ring's newest or was superseded at most
    `ROOT_GRACE_MS` (90 s) before the node's clock, the one the expiry
    check reads (`RootStale`, final for that proof: the device reads the
    feed and proves again at the newest root). Two of the device feed
    timer's longest gaps (`light-node.md` §6.7): a gateway that ends a
    device's feed answers early, at a root the ring still holds, marks the
    proofs that run for that long at most. The ring's `since` is the
    leader's batch time and this check reads the node's clock, so it
    assumes the nodes' clocks within a few seconds of the leader's; a
    leader behind by D shortens the grace here by D, and apply's bound
    holds either way;
17. a verification slot is free (`Busy`): fewer verifications in flight
    than the node's budget, by default twice its executor threads;
18. on an executor, the proof verifies under the program the binding
    names against `H_io` of the claim, computed here (`Proof`, one code
    for every failure, so a refusal says nothing of where a proof
    failed).

The origin follows the guard: the auth claim's scope and nullifier, the
owner claim's owner, or the program's id for an actor's kernel, whose
handler takes the claim as its first argument and checks it at apply (a
stock kernel's checks are the node's, above).

**A device proof** (format 47: the device profile, one masked segment
without the page-Merkle boundary, every chip at most 2^17 rows, the
proof at most 1.5 MiB; `proving.md` §8) is of a device kernel's run: one
of the credential actor's stock kernels (`auth`, `owner`), or an actor's
own. Its program (the kernel's chips, their log sizes
and the preprocessed root) is one this node computes from a release of
the installed kernel (the kernel, its reference program and its
headroom) by a run on the arguments the reference returns
(`vos_pvm_device::Program::from_kernel`), in the proof's format, never
one a request names, and kept as its verifier alone (the program, its
masked format and its id), by release and format. The
leader computes every device kernel's at the install, which fails for a
kernel whose reference, or whose run on it, does not end within the
format's shape. A replica that did not install it, or has restarted
since, computes it on an executor when a proof naming the kernel
has passed every check before the binding (format, size, expiry, guard,
claim), or a `Devices` read names it, once however many such requests wait
on it (about 0.2 s), then keeps it, and a failure of the release's own
(its shape, its runs) too; a program the replica does not hold yet, or
any other failure, answers `Unavailable` (a `Devices` read marks the
kernel's window `unavailable`) and is tried again. A window release
whose program cannot be computed admits no proof, the window's other
release still does. The guard
admits its kernel's release and, until its date, the previous release
an install replaced (`light-node.md` §4.4); a device format past its
retirement is refused `Format`. The binding names the program's id, one
of the window's; the io-hash is `H_io` of the claim, computed here, so
the proof's bytes carry no statement of their own. A run is
traced with at most 2^18 gas (`device::GAS`, twice the most steps a
program's CPU holds; about 109 Poseidon2 calls, fewer as its steps
grow), so neither the install nor a device traces far past a program's
shape; a reference program, run once a release and never proved, with at
most 2^22 (`device::REFERENCE_GAS`).

**A device kernel is trusted as its actor's code is.** A stock kernel is
the credential actor's, and what its proof states is what the kernel
computes: the stock auth kernel's member under the root and its
nullifier, the stock owner kernel's owner. An actor's own kernel is its
attestable method: one that skipped a check would admit anyone to the
guarded methods of its own instance, as a handler with no check would.
Its claim reaches its handler, which judges it at apply (a root's
freshness, a nullifier's reuse); the node's checks around the proof hold
whatever the kernel does: the binding, the replay and the claim's cap.

## At apply

Every replica applies a credentialed input by the batch's time: refused,
writing nothing, if it has expired, if its proof's device format is one
the release does not admit or the release or the agent's log retired
(`Format`: the input carries its format, so a replica whose configuration
admits more verifies such a proof for nothing), if its binding digest is
recorded
(`Replayed`, without the first call's outcome), for auth if its root is not
fresh by the batch's time (`StaleRoot`), or for a `once` guard if the
nullifier is admitted (`Once`). Otherwise the binding digest is recorded
until `expires_ms` plus a minute, whatever the method then does, and the
method runs as the origin; a `once` nullifier is recorded for good only if
the method returned `Ok`, in the same apply. An actor kernel's handler
takes the claim first, then the call's arguments. A batch runs at most 64
proven calls (`defaults::BATCH_CREDENTIALED`). So:

- **a proof replayed at another replica runs once:** both may pass their
  ingresses, the second is refused at apply;
- **a revocation binds every replica** within `ROOT_GRACE_MS` and the
  120 s horizon of the revoking batch, whatever a lagging replica's
  ingress admitted: apply judges a root at the earlier of the batch's time
  and the call's expiry less the horizon (`credentials::judged_at`), the
  latest time an ingress could have admitted the call, so no replica
  refuses at apply what an ingress admitted on the grace;
- **a format's retirement binds every replica,** whatever one node's
  ingress admits (`Admin::RetireFormat`, through the agent's log);
- **a resend past the expiry is answered the run:** a replica whose
  forward's earlier send ran is answered that run when a later send is
  refused `CredentialExpired`, not the refusal;
- **a refused vote is not a cast vote:** a handler that fails leaves its
  member free to try again with a new proof (its binding stays recorded).

A guard admits its kernel's origin alone, and a method with no guard
refuses one; no role is ever granted to a proven call's origin (a grant
naming one is `Malformed`).

## What operators learn

`Anonymous` hides a member from the log's readers, from other agents and
from other members, not from the operators of the nodes and gateways that
serve its requests:

- **No path leak from the tree's feed.** The device library keeps the
  credential actor's whole tree from its feed (`TreeKeeper`): every
  write of the tree, read a page at a time on the space's feed
  connection, each query naming its place in the feed and nothing of
  the member's, signed by a key drawn for it alone. The member's path is
  computed on the device, so no node or gateway learns which leaf is
  online. The feed is read on a jittered timer (30 s, between 15 s and
  45 s), not because a proof is about to be made, but for a first sign-in
  waiting for its leaf (every 5 s, up to a minute) and a personal agent's
  claim (`light-node.md` §6.2, §3.8).
- **A re-read after `RootUnknown`** precedes the proof that retries the
  call, at a time drawn below 10 s after the refusal, so that read's time
  links to that proof's. It happens only when the replica's ring does not
  hold the proof's root: a lagging replica, or 64 tree-changing batches
  within one timer period
  (about 1.4 a second, for 45 s), past which the library halves its
  period for the space's pace.
- **From the log:** each auth call's scope and nullifier (a pseudonym's
  activity in one scope), each payment's owner digest (a public payer),
  each proven call's claim and arguments in clear, and the metadata every
  call leaks.
- **From the root an auth call names.** The log keeps each auth call's
  `map_root` (in its claim, `CredentialedInput.claim`), which the apply
  checks for freshness. A device on the feed proves against the newest
  root it has read, the one every member who read the feed since a tree
  change holds, so the roots logged on calls link nothing beyond the
  time: within one timer period of a change (at most 45 s), the members
  who have not read it yet prove against the root before, which sets
  them apart from those who have. The log keeps the root itself, not its
  place in the ring: a place relative to the newest moves between
  ingress and apply, and a place counted from the first root names the
  root as its digest does, so it would hide nothing the newest root does
  not.
- **From a tree change:** a device reads the change as every member
  does, naming no digest; the gateway sees only that some feed
  connection read it.
- **From the tree, to any caller:** how many members there are, and when
  each was enrolled or revoked; the feed serves every write to anyone,
  and a leaf is `C(T(leaf), member)`, so whoever knows a member digest
  learns from the feed whether and since when it is enrolled, with no
  query naming it.
- **From a copied handle:** two spaces whose credential actors share a
  handle can link their common members' `member` and `owner` digests; their
  nullifiers stay apart, since the scope names the space. The app shows and
  pins a space's handle at a member's first enrollment.

**Audited** (`just test-carriers`, `node/host/tests/carriers/credentials.rs`):
a member's sign-ins and `once` votes by the stock auth kernel, a
payment by the stock owner kernel, an actor kernel's sign-in, and
ingress's refusals (a replay, `Once`, a cut proof, another call's
arguments, an expired call, an unregistered format, an actor kernel's
proof sent to a stock guard, two frame errors), over the API's socket and a
gateway relaying onto the API over QUIC. No carrier holds the member's
device secret (its source's output, `w`, `s`, the nullifier's key, their
hashes, a kernel's arguments; `s`'s single words in what leaves
the device) or a proof's masks as drawn: every byte the socket's
connections carried each way, each HTTP request and its answer's status
and body as sent and read through the gateway, each node's log entries,
work results, store, disk and frames, the device library's values as
`Debug` and `Display` show them, and
every log line of the nodes and the gateway at every level. The QUIC
frames between the gateway and the nodes are not taken apart from the
TLS: their bodies are the HTTP bodies above, framed by the same codec as
the socket's. And no carrier of a credentialed call holds where its
member sits (its digest, its leaf, its occupied siblings): the call's
bytes each way, its answers, its log entries, the logs. Only the feed's
connection does, which carries the whole tree to every member, though
not the member's digest. The member's slot is searched for as a number
only from 2^20 up (`carriers::SMALL_FLOOR`): a smaller one's digits are in
any log by chance, so a slot under 2^20 is searched for through its
digest, leaf and siblings alone.

## The demo's SSH surface

The gateway's SSH port serves s4's screens and the `vos-api` subsystem to
a member's phone, for the demo in s4 (`node/gateway/demo`): enroll, sign
in and pay, the proofs made on the phone by s4's `vos.credential`
facility (`identity-and-authority.md` §7):

- **No one in particular.** The port takes any public key as an identity
  for its connection alone (s4's anonymous policy): no session is parked
  or resumed, and no remembered grant is selected (on the client, s4
  keeps a session's grant for a reconnect it makes by itself,
  `light-node.md` §6.2; the server sees a new, granted session). The
  client draws a key for each connection, and another for each `vos-api` connection that
  reads the tree's feed or the node's time, so no two of them share a
  key. Keys are all that stops linking them: the gateway still sees their
  address and timing. The feed names no member, and the client reads it
  on its own timer (`TreeKeeper`), not on the way to a proof, except a
  first sign-in waiting for the operator's invitation, which reads it
  every 5 s and proves seconds after the root that lists its leaf.
- **The root a proof names.** A proof names the root of the tree the
  client built from the feed, each page checked against the root its last
  change names, so a gateway cannot hand one member a path to a root of
  its own making but by serving that member's address a feed of its own:
  a gateway that marks an address's feed with a root of its own learns
  which member proves on it. Roots the node signs, under a key pinned at
  enrollment, would close this; until then, the gateway is trusted not to
  mark roots.
- **What the server can steer.** The screens are the gateway's document;
  the proofs are the client's facility's (`vos.credential`), which shows
  its own forms in the client's chrome and acts on what the user confirms
  there. A payment's payee and amount are the chrome form's, the server's
  request only a pre-fill; a sign-in's chrome names the method and, for a
  `once` guard, that it spends the member's one admission in its scope; the
  space, agents and methods the device proves for are shown and pinned at
  its first enrollment, and a later request naming others is refused by
  the client. What enrollment pins is the gateway's word, shown to the user
  once, as a host key is: a hostile gateway at enrollment can mislabel a
  method's guard, and the node's guard still decides what a proof admits.
  A device kernel pinned with a method at enrollment is the gateway's word
  too. A kernel other than the installed one proves nothing at the node,
  whose binding names the installed kernel's program. The device runs it on
  the member's secret and path: its proof states the io-hash alone, which
  the library checks is the one of the claim it computed before the proof
  leaves the device, and the masked proof hides the run. What a hostile kernel still steers is
  whether its run fits its program's shape, so whether the device answers
  a proof or an error, and how long the refusal takes (the run is traced
  to at most `device::GAS`): a few bits a sign-in.
- **What the gateway relays.** It forwards a facility's `Credentialed`
  request as it is, after checking it names the demo's agent and the
  screen's instance and method; any other is refused before a node sees
  it. It holds no credential bytes, builds none, and its app key sends only
  the claims (`claim(member)`, `open`) the operator's invitations name.
  The binding names the space, so a proof made for another space fails the
  node's `Binding` check whoever relays it.
- **The enrollment's digests** are shown in the client's chrome, never in
  the gateway's screen, as a code a camera reads (`VOSENROLL1:`) and a
  six-digit check; the operator scans or pastes the code into its tool,
  which shows the same check, and invites them only once the two checks
  match. The check catches a misread code or the wrong screen; it proves
  nothing about who chose the digests. A gateway's
  screen therefore cannot have its own digests invited in the member's
  place, and the claim it relays names only digests an invitation holds.
- **Time.** The calls' expiries are reckoned on the node's time, which the
  gateway answers; the client refuses a time more than five minutes from
  its own clock, so a gateway can stretch a call's life by at most that.
- **A proof the gateway holds back.** The gateway may withhold a proof it
  relays and submit it later, until the call's expiry; it cannot alter it
  (the binding covers the call) or make another from it. Asking again for
  the same payment within its expiry yields the same request, so a retry
  after a withheld one cannot pay twice; a `once` guard's nullifier admits
  it at most once whenever it lands.

## The onion

A space's gateways host its onion service in process (arti, `vos-gateway`'s
`tor` feature; `light-node.md` §6.1, §6.6, §6.7): its port 22 is the
gateway's SSH (s4's screens and the `vos-api` subsystem, whose relay set
holds `Call` and `Credentialed`), any other port refused, port 80 among
them until an HTTP client exists (E23). What that changes for the node and its operators:

- **What Tor fixes:** no node or gateway learns a Tor client's network
  address, so a proof's nullifier, a feed read and a personal agent's
  traffic arrive with no address behind them, each on a circuit of its
  own (one a purpose, `node/light/SECURITY.md`); a gateway that marks a
  feed with a root of its own (above) loses the address it would have
  linked the proof to, and keeps only the circuit.
- **What Tor does not fix:** the timing of a feed read and a proof, which
  a gateway sees on two circuits it may correlate by time; the `map_root`
  a proof names, which within a timer period of a tree change sets apart
  the members who have not read the change (above); small anonymity sets
  (a tree of fifty is fifty however the bytes travel); a global observer
  correlating both ends of Tor; what a request carries itself (a member's
  signed call names its key, a personal agent's call its sync key); and
  Tor's own maturity: arti's onion-service hosting is not declared
  production-ready, and its service-side proof of work is behind the
  `tor-pow` feature, off by default.
- **The transport mark.** The gateway marks every frame with the
  transport it took (`Mark::Onion` for the onion's ports, `Clearnet`
  otherwise), whatever the client marked; the node's ingress may refuse
  anonymous calls without the onion's mark, or every request
  (`onion = "anonymous" | "all"`, `node-api.md` §3). The mark is the
  gateway's word: a space trusts its gateways to mark truly, as it trusts
  them to relay. A personal agent takes nothing without it (E17).
- **No address to limit.** A Tor client has no address, so the
  gateway's limits per address count each circuit as an address of its
  own, and cap streams a circuit, circuits at once, proven calls in
  flight through the onion, from one connection and from one circuit,
  and an agent's calls from one circuit (`node-api.md` §6). A client may
  open as many circuits as Tor lets it: the per-circuit caps bound one
  circuit (a proven call's header takes its circuit's places before it
  waits for the onion's, one waiter a circuit, and a body that falls
  behind its pace gives them back after about 5 s), the onion's global
  caps and the
  node's verification budget bound them all; the members' wait grows
  with the attacker's circuits (about C × 5 / 16 s, `light-node.md`
  §6.6), whose bound past that is the introduction rate and arti's proof
  of work; and a flood of well-formed junk proofs through a
  private Tor network was held by Tor itself to about fifteen a second,
  members' sign-ins served throughout (`light-node.md` §6.6, measured on
  chutney, not on the live network).
- **Not capped per circuit:** the demo's screens' own calls (s4's
  host-service calls carry no peer), which only the server's bound per
  session holds; and the onion's SSH server takes s4-server's connection
  cap (128 unless `[onion] ssh_connections` sets it, each connection given
  30 s to authenticate) with no idle close of its own
  (`docs/design/open.md`).
- **The onion's key is the gateway's identity,** self-authenticating:
  a gateway that holds it is the space's onion, and the registrar serves
  the space's onion set unsigned (`set_onions`, `onions`), as any answer a
  gateway relays (`light-node.md` §8, H5). A client pins the set and each
  onion's SSH host key at enrollment and refuses a host key it did not
  pin. s4 (on Android, with the facility) refuses to go on with its own
  clearnet connection to a gateway presenting a key a space pinned to its
  onion, however its name or port is written: a guard against a
  misspelled gateway, not a hostile one. The check comes at the key
  exchange, so the gateway has seen the device's address by then, and a
  gateway presenting another key on its clearnet port is not caught.
- **Audited** (`just test-carriers`, `node/gateway/demo/tests/carriers.rs`):
  a member's sign-ins by the stock auth kernel (one of them proved with
  its masks' randomness watched), a cut proof and an owner's payment, each
  made by the light node's Tor client and carried by the gateway's onion
  in process (each stream handed to the onion's SSH port on a circuit of
  its own, as arti hands them), the tree read from its feed on one
  connection and the node's time on others. No carrier holds the member's
  device secret or a proof's masks: each circuit's bytes each way, what
  the client sent and read on each purpose's connections, every frame
  the gateway relayed to the node and its answers, the light node's
  values, every log line of the process at every level, standard error,
  and the node's store, log and disk. No carrier of a proven call holds
  where its member sits; the feed's connection and the gateway's frames to
  the node hold the whole tree by design, not the member's digest. Tor's
  own cells (arti's onion encryption) are not in the test: the streams are
  handed over in process.

## The home and its personal agents

A home is a space whose agent holds the credential actor and `Homes` in
front of a pool of personal agents (`light-node.md` §3.3); each agent runs
`Personal`, holds a user's ciphertext and a small log of rare operations,
and takes requests only through the onion, only from the keys its log
admitted. What its operators are trusted with, and the limits that stay
(`light-node.md` §8.2, §8.8):

- **Trusted for availability, order and time, not for contents:** the
  operators can withhold or delay sync (devices work offline as full
  replicas, and after 7 days without the agent the app offers to move
  home, B1), delete envelopes (each device samples what it pushed and
  pushes again what is missing, B2), roll an agent back or equivocate
  (raising an alarm on the control log's chain and the views sealed in
  envelopes, though nodes sign nothing a device could show a third party,
  B3, B4), and advance the agent's clock to mature a hostile removal or
  restore early (B7): every delay trusts the operators' clock, a known
  limit. They cannot forge an envelope (B5) or a device-set operation,
  each signed by a device's admin key or the kit and checked by every
  device, nor log a signed call again on a forked log, each naming its
  place (B6, `light-node.md` §3.5). They can withhold: a device that has
  not yet read a veto can be shown the operation without it (B8).
- **Collusion with a thief or a removed device** can drop vetoes, order
  the thief's operations first and serve a removed device data for up to
  six days; acting alone they can hold back a genuine commit until a
  device is quiet and name it absent, locking it out until it re-pairs or
  regroups (B8). The owner's remedies are two seasoned devices' immediate
  removal and moving home.
- **What the operators see:** the agent's id, its sync keys and admin
  keys, each scope's opaque id, the sizes, counts and times of its
  envelopes and commits (padded, not hidden, C8), its quota and lease; not
  a byte of the user's data. At a home-only space the claim's open claim
  names no member the operators know elsewhere (a joiner makes none,
  E28); a home
  that is the user's own space links the agent to the member (L1, L5),
  which the app states.
- **The lease and the pool.** An agent lapses when its yearly re-proof
  stops (an expelled member's included), 13 months after the last, into
  180 days of grace in which it serves reads, a restore and a removal,
  and refuses pushes (B14); reaping after the grace is later work.
  No device makes the re-proof yet (`light-node.md` §1.1), so every agent
  lapses 13 months after its claim unless the home sets a longer lease
  (`docs/design/open.md`). A move home is a leave and a new claim: the
  old home keeps what it held, and its agent lapses in time. Open claims are bounded by a daily cap
  and work, a bound on griefing and not a price (L11); the pool's
  `PoolEmpty` and the cap's refusal stop claims, never another user's
  agent (B11).
- **A home with one replica** loses the agent with its node; devices stay
  full replicas, and the chrome shows the replica count (B10).

## Replay and custody

- **A replay answered by a replica that forwarded it** (`Replayed`, the
  call having run by an earlier send or another replica's copy) is
  answered once that replica has applied the binding, so a client that
  reads state there reads the first run's effects.
- **Replay** is bound by the binding digest: another space, agent,
  instance or method, other arguments or another statement change it, so
  the proof fails `Binding`; a proof is good for 120 s at most; and its
  digest, recorded at apply until it expires, makes it run once across
  every replica. A proof intercepted in flight can be sent by the
  interceptor before its owner: it is the same call, run once. The
  transports keep it from on-path observers (the node API's QUIC, a
  gateway's TLS or SSH); a gateway sees every proof it relays and can do
  the same, and nothing more.
- **Revocation does not stop payment.** An owner proof reads no tree: the
  ledger's handler compares the row's live owner with the proof's digest.
  The ledger's `rekey` and `freeze`, under an operator role, stop a thief
  of a secret; an operator who can `rekey` can move any row, so the
  in-space ledger is custodial by design, each `rekey` attributed in the
  log to the operator's origin.

## Denial of service

- Every check but the proof's costs microseconds and runs first; the
  frame's size is refused from its header, at a gateway's HTTP from the
  head.
- There is no bucket per scope or method to drain: the bounds are the
  node's connections and its verification budget, past which a call is
  answered `Busy` before its proof is decoded; a statement with a word at
  or above p is refused `Proof` without spending a verification.
- Credentialed bodies past a call's size (every one with a proof) take
  places of their own, 64 at once on the node's socket and QUIC together
  (about 100 MiB at the largest), apart from the installs' four: past
  them, QUIC answers at once from the header, the socket reads the next
  only as one ends. A body is
  dropped once decoded, and its place given back with its proof once the
  proof is verified, never held through the apply or a forward's wait:
  the places bound proofs held and verified at once, so 64 valid proofs
  sent to a follower of a slow leader hold none of them past their
  verifications. The gateway's HTTP keeps a body, and its place, until
  the node answers, as it relays the body whole: its 64 places bound the
  credentialed calls in flight through one gateway, under its limits per
  address.
- A binding digest's row is forgotten by the sweep, up to 64 a sweep, in
  an index of its own beside the sessions' and workflows' rows, so due
  bindings never hold one of those back; a batch runs at most 64 proven
  calls (`defaults::BATCH_CREDENTIALED`, a rule of refine's: the first
  past them cuts the batch short, and the leader holds the rest for the
  next), so the sweeps, one a batch while rows are due, forget bindings
  as fast as batches record them.
- What a proof costs a verification slot, on one x86 core (medians and
  95th percentiles of 200 runs): before the proof is decoded, a
  pre-check reads its leading fields and checks its interaction PoW over
  the program, its first two roots and the io-hash; then the decode and
  its canonical re-encoding, the interaction PoW again, the logup totals,
  the composition at the OODS point, the PoW, and the decommitments. A
  program's masked format is computed once, when the program is
  installed or pinned, not per proof; its component layout is still
  built per proof, within the verification's time. A device proof of the stock auth
  kernel (about 870 KB) [measured, x86 development desktop (Intel Core
  Ultra 7 155H), one thread, load average 7–21 from other builds,
  2026-11-06; `cargo run --release -p vos-phone --example
  verify_cost`]:
  - verified in 16–48 ms by the load (11.7 ms on a quiet machine,
    2026-11-01);
  - a wrong interaction PoW, a main root changed, or the honest proof
    against another claim's io-hash: refused by the pre-check in
    0.017 / 0.021 ms;
  - a wrong PoW: 11–27 ms, after the decode (3.2–8.8 ms, of which the
    re-encoding is about half) and the composition;
  - one cut short: 1.6–3.5 ms, a decode to its end.

  The format's interaction PoW is 8 bits, so junk ground for 2^8 nonces,
  microseconds of work, passes the pre-check; the next check an
  attacker cannot meet cheaply is the 16-bit PoW, after the decode and
  the composition. Refusing such junk in under 1 ms needs a heavier
  interaction PoW, a format change (`docs/design/open.md`).
- **The executors' verification gate** [decided]: at `k` verifying
  threads, at least `100·k` credentialed calls a second, scaling linearly
  to `N` threads, p99 within 50 ms of a signed call's at the same rate;
  no absolute rate is claimed. Measured with `k` = 1, 2, 4 and up to the
  host's physical performance cores, the node pinned to those cores, the
  load generator on another machine over QUIC, each run at least 10 s,
  and `N` recorded as the physical cores and the logical threads
  (`cargo bench -p vos-node --bench credentialed`, its `serve` and
  `drive`). `100·k` a second on `k` executors leaves each call 10 ms of
  an executor, verification and apply together: a device proof's
  verification alone takes about 12 ms on a quiet x86 core, so the bench
  drives `50·k`, and the gate's rate for device proofs is open
  (`docs/design/open.md`).
- The request's decode and the device verifier's bytes are fuzzed
  (`node/fuzz`'s `credentialed_decode`, `pvm/proof/fuzz`'s
  `device_verify_bytes`).
- The gateway adds its own limits per address before any of this.
