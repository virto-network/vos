# The node's credential surface: security considerations

What a node takes on when it serves credentialed calls, calls whose
authority is a credential proof rather than a client's signature: what
ingress verifies and in what order, what the log keeps, what the operators
and the gateways that relay requests learn, and where the node is open to
denial of service. It is descriptive, not a formal argument. The design is
`docs/design/identity-and-authority.md` (§5 the request, its checks and
the apply rule; §6 the credential actor; §7 the threat model) and
`docs/design/proving.md` §8 (the statements). What the device library
holds is `pvm/device/SECURITY.md`'s, and what a verified proof proves is
`pvm/proof/SECURITY.md`'s.

## Who is trusted

- **A space trusts its nodes.** Ingress verifies the proof and logs only
  the origin it proved, `Anonymous { scope, nullifier }` for an auth
  proof or `Owner(digest)` for an owner proof, never the proof. Every
  replica applies the origin as logged; none verifies again. An operator
  can therefore log an origin it never verified, as it could run any call:
  members trust their space's nodes for integrity. A space that wants
  evidence keeps the proofs in the non-repudiation side store (not built).
  Likewise a replica forwards a verified call to the agent's leader with
  its origin alone, and the leader takes it as a replica's word.
- **A gateway holds no authority.** It translates
  `POST /agents/{agent}/credentialed` and `GET /time` onto the node API
  and runs none of the checks: every check is the node's, whoever relays
  the frame. A compromised gateway can drop, delay or reorder requests and
  read what it relays; it can forge nothing.
- **The node's clock** (`Time`) is unsigned. A relay that lies about it
  makes the client pick an expiry the node refuses, which costs a new
  proof; it cannot extend a proof's life, since ingress judges the expiry
  by its own clock, at most 120 s ahead.

## What ingress checks, in order

Each check is cheaper than the next; every one but the last reads the
request and this replica's applied state alone. A refusal is
`Rejected(Credential(code))`, the codes in this order (the node API's
frame checks and the agent's placement come first, as for any call):

1. the frame within its kind's size (1,642,496 bytes), from its header,
   before a byte of the body is read; over HTTP from the request's head;
2. the body decodes exactly;
3. this node serves the agent;
4. the agent's space has a genesis (`NoSpace`): a binding names its
   `SpaceId`, and no proof may bind `NONE`;
5. the format is one this node admits for a credential (`Format`): the
   credential format the proof registry names, as the final verifier pins
   it; a device proof's is refused until a device kernel is admitted;
6. the proof within its format's cap (512 KiB), the arguments within
   `cap::REQUEST` (`Size`);
7. `now ≤ expires_ms ≤ now + 120 s` by the node's clock (`Expiry`);
8. the method exists and carries a credential guard (`Method`);
9. the statement's kind is the guard's (`Kind`);
10. for auth, the scope is the one the guard's name gives in this space,
    agent and instance (`Scope`);
11. the binding is this request's (`Binding`): its space, agent,
    instance, method, statement program and kind, arguments, nonce and
    expiry;
12. the binding digest is not recorded (`Replayed`);
13. for a `once` guard, the nullifier is not admitted in its scope
    (`Once`);
14. for auth, the root is in the credential actor's ring (`RootUnknown`,
    retryable: an honest member meets it on a lagging replica, after a
    later write replaced its root at the same batch time, or once 64 later
    roots pushed it out; it fetches its path again or asks another
    replica);
15. for auth, the root is the ring's newest or was superseded at most
    `ROOT_MAX_AGE` (10 minutes) before this replica's latest batch time
    (`RootStale`, final);
16. a verification slot is free (`Busy`): fewer verifications in flight
    than the node's budget, by default twice its executor threads;
17. on an executor, the proof verifies under the program its kind names
    (`Proof`, one code for every failure, so a refusal says nothing of
    where a proof failed).

Ingress calls the final verifier's `credential::verify`, which picks the
circuit by kind, never the circuit-generic step beneath it, which takes
any preprocessed root.

## At apply

Every replica applies a credentialed input by the batch's time: refused,
writing nothing, if it has expired, if its binding digest is recorded
(`Replayed`, without the first call's outcome), for auth if its root is not
fresh by the batch's time (`StaleRoot`), or for a `once` guard if the
nullifier is admitted (`Once`). Otherwise the binding digest is recorded
until `expires_ms` plus a minute, whatever the method then does, and the
method runs as the origin; a `once` nullifier is recorded for good only if
the method returned `Ok`, in the same apply. So:

- **a proof replayed at another replica runs once:** both may pass their
  ingresses, the second is refused at apply;
- **a revocation binds every replica** within `ROOT_MAX_AGE` of the
  revoking batch, whatever a lagging replica's ingress admitted;
- **a refused vote is not a cast vote:** a handler that fails leaves its
  member free to try again with a new proof (its binding stays recorded).

A guard admits its credential's origin alone, and a method with no guard
refuses one; no role is ever granted to a credential's origin (a grant
naming one is `Malformed`).

## What operators learn

`Anonymous` hides a member from the log's readers, from other agents and
from other members, not from the operators of the nodes and gateways that
serve its requests:

- **The path leak, reduced, not closed.** Asking the credential actor for
  `path(member)` tells the operators which member digest is online, and
  from which address. What they do not learn is when it proves:
  - the device library (`PathKeeper`) fetches its path apart from its
    proofs: on a timer of 30 s jittered uniformly between 15 s and 45 s,
    and at a time drawn below 10 s after a moved `root()` answer is first
    seen, never because a proof is about to be made; the client sends
    the queries on a connection of their own;
  - each `path` and `root()` query is signed by a key drawn for it alone,
    so a fetch links to no client key; `root()` names no member;
  - so a fetch's time says nothing of a proof's, but a proof from the same
    address still links its nullifier to the digest, and the digest to
    whoever the registrar enrolled.
- **A refetch after `RootUnknown`** precedes the proof that retries the
  call, so that fetch's time links to that proof's. It happens only when
  the replica's ring does not hold the proof's root: a lagging replica, a
  root replaced at its own batch time, or 64 tree-changing batches within
  one timer period (about 1.4 a second, for 45 s), past which the library
  halves its period for the space's pace.
- **From the log:** each auth call's scope and nullifier (a pseudonym's
  activity in one scope), each payment's owner digest (a public payer),
  each credentialed call's arguments in clear, and the metadata every
  call leaks.
- **From a tree change:** every online member's library fetches its path
  within 10 s of seeing `root()` move, so each enrollment or revocation
  shows which member digests are online then; the spread, and the
  clients' own jitter in polling `root()`, spread the fetches, they do
  not hide them. Syncing the tree is the later fix.
- **From the tree:** how many members there are, and when each was
  enrolled or revoked.
- **From a copied handle:** two spaces whose credential actors share a
  handle can link their common members' `member` and `owner` digests; their
  nullifiers stay apart, since the scope names the space. The app shows and
  pins a space's handle at a member's first enrollment.

## The demo's SSH surface

The gateway's SSH port serves s4's screens and the `vos-api` subsystem to
a member's phone (`slice-7-mobile.md` 7.13):

- **No one in particular.** The port takes any public key as an identity
  for its connection alone (s4's anonymous policy): no session is parked
  or resumed, and no remembered grant is selected. The client draws a key
  for each connection, and another for each `vos-api` connection that
  fetches its path, the root or the node's time, so no two of them share a
  key. Keys are all that stops linking them: the gateway still sees their
  address and timing, and a proof from the address that fetched a digest's
  path links its nullifier to that digest, as above. The client fetches
  its path on a schedule of its own (a drawn first delay, a spread on each
  refresh, at most one refresh in thirty seconds), not on the way to a
  proof, which loosens the timing link without removing it.
- **The root a proof names.** A path is used only if its root is one of the
  last roots the client's own root polls saw, so a gateway cannot hand one
  member a path to a root of its own making and know the member by it. A
  gateway that answers every poll of one member with roots no one else sees
  can still mark that member; the node accepts only roots its tree held, so
  such a proof fails rather than passing unnoticed.
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
- **What the gateway relays.** It forwards a facility's `Credentialed`
  request as it is, after checking it names the demo's agent and the
  screen's instance and method; any other is refused before a node sees
  it. It holds no credential bytes, builds none, and its app key sends only
  the claims (`claim(member)`, `claim_row`) the operator's invitations name.
  The binding names the space, so a proof made for another space fails the
  node's `Binding` check whoever relays it.
- **The enrollment's digests** are shown in the client's chrome, never in
  the gateway's screen, which only asks the member to read them from there
  to the operator; the operator invites them out of band. A gateway's
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
  frame's size is refused from its header, over HTTP from the head.
- There is no bucket per scope or method to drain: the bounds are the
  node's connections and its verification budget, past which a call is
  answered `Busy` before its proof is decoded; a statement with a word at
  or above p is refused `Proof` without spending a verification.
- Credentialed bodies past a call's size (every one with a proof) take
  places of their own, 64 at once on the node's socket and QUIC together
  and 64 on the node's HTTP (about 100 MiB at the largest), apart from
  the installs' four: past them, QUIC and HTTP answer at once from the
  header or head, the socket reads the next only as one ends. A body is
  dropped once decoded, and its place given back with its proof once the
  proof is verified, never held through the apply or a forward's wait:
  the places bound proofs held and verified at once, so 64 valid proofs
  sent to a follower of a slow leader hold none of them past their
  verifications. The gateway's HTTP keeps a body, and its place, until
  the node answers, as it relays the body whole: its 64 places bound the
  credentialed calls in flight through one gateway, under its limits per
  address.
- A binding digest's row is forgotten by the sweep, up to 64 a sweep
  beside the 32 sessions' and workflows' rows it lists, a sweep a batch
  while rows are due: sustained credentialed calls past 64 a batch grow
  the binding rows until the load falls, and while more than 96 bindings
  are due before a session's or a workflow's row, that row waits for them
  to drain.
- A proof's verification takes about 2 ms on one x86 core; one whose PoW
  is wrong is refused in about 0.7 ms (the composition check runs before
  the PoW in the verifier's order), one cut short in about 0.2 ms
  [measured, `slice-7-progress.md` 7.11].
- The request's decode and the verifier's bytes are fuzzed
  (`credentialed_decode`, `credential_verify_bytes`).
- The gateway adds its own limits per address before any of this.
