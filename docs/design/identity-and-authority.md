# Identity and authority

Who acts in a space, how a request proves it, what each actor may do,
and what anyone outside a space learns. VOS builds primitives (origins,
attestations, credentials, proofs, personal spaces) and each space
composes its privacy model from them. The in-space credential (§5–§7)
is built: the credential actor and its tree, credentialed calls at the
node API's ingress, the `once` guard, device proofs, signed operator
requests, and the device library with the `vos.credential` facility.
Full privacy (§8) is postponed; known gaps and next work are in
`open.md`.

Tags as in the core model: **[decided]** a settled choice, **[built]**,
**[measured]** by a run; the rest is proposed.

## 1. Requirements

- **Members of different weight.** Some members run nodes in an agent's
  consensus. Some run light nodes that sync only a few agents or
  actors. Most run no node at all and use the space through HTTP, SSH or
  an app reaching nodes that stay up.
- **A stable identity, controlled by devices.** As Kreivo's pass does:
  - one identity, controlled by an ed25519 key, a passkey, an SSH key or
    another device;
  - or a proof of membership that does not reveal which member acts.
  - VOS identity stands alone; Kreivo may move onto the agents-on-JAM
    model.
- **Primitives, not a privacy policy** [decided]:
  - Some spaces will trust their operators and want nothing more.
  - Others will want actions hidden even from operators.
  - VOS provides the primitives (agents, extensions, origins,
    attestations, proofs, personal spaces) and never imposes a model.
    Each space composes what fits it.
- **One trust model per space:**
  - a space's operators see everything in it;
  - privacy from them comes from keeping secrets out of the space: data
    encrypted to its members, or kept in a space of one's own (a
    personal space) that sends a shared space only proofs.
- **Portable standing, not a portable handle.** Reputation, financial
  standing or other facts held privately in one space may be useful to
  another. Carrying them across is wanted; a global identifier that
  links a person everywhere is not.
- **A root space.** A first space (Virto) that people join to register
  new spaces, which may charge fees, and which governs, as a DAO, the
  policies registered spaces follow.
- **VOS and JAM working together.** Spaces stay private and put on JAM
  only what other spaces or the JAM world need. Actors on each side
  call each other under a permission model, and the space's attestable
  proofs disclose the minimum.

## 2. What is built

- **A caller is a principal:** a client's key or another agent.
- **Each agent keeps a table** from principals to role bytes, set by the
  operator's CLI, and a handler names the role it needs. A workflow's
  role is checked at its start.
- **Clients sign each request** with their key, inside a session the
  client names.
- **Ingress authenticates clients into principals,** and the agent
  receives the authenticated origin. Guests never check signatures
  (core model §5). The ingress is the node's binary API; a gateway in
  front of it relays and holds no authority [decided] (`node-api.md`).
- **Proven calls** carry a device kernel's proof and its claim instead
  of a signature and a session: ingress verifies it and logs the origin
  it proves, `Anonymous` (a pseudonym in a scope), `Owner` (a digest) or
  `Kernel` (an actor kernel's program) (§5–§7).
- **Operator requests** are signed by an operator key the node lists,
  with a nonce and an expiry (§6).
- **Nodes** have keys of their own, and a space's nodes trust each other:
  the trust model is crash faults only.
- **No identities, devices or delegation;** anonymous callers only
  through the in-space credential.

## 3. Two axes, and the primitives for each cell [decided]

Secrecy and anonymity are different things, so they are two axes, not
one tier. A space picks the cells it needs; each cell names the
primitives that serve it.

| | **Actor named** | **Actor anonymous** |
|---|---|---|
| **Data the operators can read** | plain actor state, signed origins: most spaces | anonymous origins with a scoped nullifier: votes, polls, rate-limited posting |
| **Data hidden from the operators** | data encrypted to its members, as the messenger's end-to-end encryption does | a personal space plus a shielded pool: private payments (postponed) |

- **A space's own trust model holds in every cell:** its operators see
  what is in it. What they cannot read was never given to them in clear.
- **Facts proven about oneself** (credentials, §7) need no secret state:
  a prover shows a fact and stays unlinkable.
- **Across spaces,** every cell discloses only what a proof returns.
- **Metadata** (network addresses, timing, sizes) leaks in every cell.
  Tor hides the network address (`light-node.md` §6, whose §6.7 names
  what it does not fix); anonymous calls go only over it.
- **What is built:** the top-left cell, and with the messenger, the
  bottom-left; the top-right in a space, through the membership
  credential (§5–§7); the bottom-right is postponed (§8).

## 4. Five concepts

| Concept | Answers | Lives in |
|---|---|---|
| **Identity** | who, stably, in one space | the space's identity agent |
| **Authenticator** | how a request proves it speaks for an identity | a device key, a passkey, an SSH key, a hardware token |
| **Origin** | who a running call acts for, as the agent sees it | every logged input |
| **Attestation** | a claim an issuer makes about a subject, valid until a time, revocable by its issuer | issued by actors; shown in clear as a grant, or proven in zero knowledge as a credential |
| **Membership** | a principal's relation to a space, on independent axes | the space's roster |

- **A pseudonym** is just an identity in another space (§7).
- **A scope** is a field of an attestation.
- **An anonymous membership proof** authenticates no identity, so it is
  not an authenticator: it is an origin (§5).

## 5. Authority: origins, attestations and guards

**Authority is verified at the executor's trust boundary** [decided],
and there are two kinds of executor:
- **A space** trusts its nodes. This includes the space's own agents
  deployed on JAM, whose builder is one of its nodes.
  - At ingress, a request's evidence (its device's signature, the
    attestations it presents) is reduced to an origin plus an authority
    set: the claims it was shown to hold, narrowed.
  - The log entry carries the origin and the authority set, never the
    evidence.
  - A guard reads only the logged origin, the authority set and state.
    So every replica, and a JAM witness, evaluates the same bytes.
  - Its guests never verify signatures. On JAM there is no signature
    precompile, and a software verification would be paid by every
    replica.
- **A public JAM agent,** such as the registry (§12) or a shared pool
  (§8), trusts only the chain and proofs. Its builder is anyone.
  - Its inputs are:
    - `Jam { service }` origins, which the chain authenticates, such as
      a transfer from a registered space's representative;
    - proofs it verifies in its guest;
    - anonymous inputs whose proof is their authority.
  - **It never takes an origin from its builder,** which could
    otherwise log an invented one that no witness would catch: the
    witness covers state, not evidence.
  - So registration and votes arrive as transfers from the registering
    space's representative.
- **A claim that strangers must be able to check** is a proof, verified
  in the guest of the agent that relies on it. Examples are a
  settlement claim between spaces, a spend into a shielded pool, and a
  credential.
- **No signatures in the log** means an operator cannot prove to an
  outsider what a member did: deniability for members. Spaces that need
  non-repudiation for disputes can turn on an ingress option, off by
  default, that keeps request signatures in a side store.

**The rule:**

> Authority is verified at the executor's trust boundary. A space's
> boundary is its nodes' ingress, which reduces evidence to an origin
> and an authority set that the log carries; guards read only those and
> state. A public JAM agent's boundary is the chain: its origins are
> chain-authenticated services, proofs it verifies in its guest, and
> anonymous inputs whose proof is their authority; it takes no origin
> from its builder. Evidence is never logged; non-repudiation is a
> side store.

**What an authority set carries:**
- the ids (hashes) of attestations already installed in the agent's
  state, such as roles and standing grants;
- inline, only ad-hoc delegations, narrowed at ingress to their
  intersection with what the delegator holds.

It has a deterministic encoding, since every replica and the witness
compare it, and on JAM its size is paid as payload.

**The kinds of origin,** each a variant of the logged caller
(`vos_abi::ids::Principal`) with its codec index:
- `Client(key)`, 0: a client's ed25519 key, in a session it signs. The
  identity agent (§6) turns it into `Identity { id }`, a person or service
  in this space through a device, at index 5, reserved;
- `Agent(id)`, 1: another agent of this space;
- `Instance(id)`, 2: the calling instance of the same agent, for a nested
  call;
- `Anonymous { scope, nullifier }`, 3: the stock `auth` kernel's. The
  sender knows the secret behind a member's leaf; `nullifier` is its
  pseudonym in `scope` (§7, `proving.md` §8), stable across its calls;
- `Owner(digest)`, 4: the stock `owner` kernel's. The sender knows the
  secret behind `digest`, the owner an account names: a public payer
  [decided];
- `Jam { service }`, at index 6, reserved: a JAM service, authenticated by
  the chain or a light client;
- `Kernel { program }`, 7: an actor's own device kernel's, `program` the
  id of the kernel's program the proof is of; its handler takes the
  kernel's claim and judges it (`light-node.md` §4).

Each digest is 32 bytes, eight M31 words as little-endian `u32`s. No role
is ever granted to an `Anonymous`, `Owner` or `Kernel` principal: a
`Grant` naming one is `Malformed`.

**A collective decision is not an origin kind.** It is a message from a
governance agent carrying an attestation (`decision(d)`). A guard that
wants one says "from agent G, with claim `decision(d)`".

**Attestations, one primitive used two ways** [decided]:
- **The record:** issuer, subject, claim, validity, and the issuer's
  revocation epoch at issue.
- **In clear:**
  - **grants** inside a space, delegated and narrowed, for example "this
    app may call `transfer` on actor A, up to 100, until Friday";
  - **roles,** named claim sets an issuer grants. `#[msg(role = ..)]`
    stays, as one kind of guard.
- **Committed:** a salted leaf under the issuer's anchored root,
  provable in zero knowledge as a **credential** (§7).
- **The issuer chooses the committed form** at issue, so a grant that
  never leaves the space pays nothing for anchoring. One fact per leaf,
  so a holder proves one fact and nothing else.
- **Object capabilities** are the special case where a grant names one
  instance and one method.

**Revocation by epochs** [decided]:
- each identity, and each device under it, has a revocation epoch in
  the identity agent;
- a grant carries its issuer's epoch at issue;
- bumping the epoch voids every earlier grant, at one local read at
  ingress;
- a device's epoch revokes a lost phone without touching the person's
  other devices;
- **a bump also voids long-lived grants issued before it,**
  deliberately. Roles the space grants come from a system identity
  whose epoch rarely moves, so the common case is unaffected;
- short expiries, in batch time (monotone, core model §8.4), cover the
  rest;
- a list is kept inside a space only to revoke one particular grant;
- credentials across spaces lapse by freshness (§7). No revocation list
  ever crosses a space boundary, so none leaks who was revoked.

**Proven calls** [decided]: a call whose authority is a device kernel's
proof (format 47, `proving.md` §8; `light-node.md` §4), with no session
and no signature. Ingress verifies the proof and logs the origin it
proves and the kernel's claim.
- **The request:** `Credentialed`, a request kind of the node's binary
  API (`vos_wire` frames over a unix socket or QUIC with mutual TLS)
  addressed to an agent [decided]. Its kind is read before its body,
  so the node sizes the frame before decoding it: at most 1.5 MiB plus
  `cap::REQUEST` plus the 4 KiB envelope. A gateway serves it over HTTP as
  `POST /agents/{agent}/credentialed`, `413` past the size; the gateway
  translates and holds no authority, and every check below is the node's.
  The body, in SCALE:

  ```rust
  pub struct Credentialed {
      pub instance: InstanceId,
      pub method: MethodId,
      pub arguments: Vec<u8>,          // at most cap::REQUEST - cap::CLAIM
      pub nonce: [u8; 16],             // the client's, at random
      pub expires_ms: u64,             // by the node's clock
      pub format: u32,                 // 47, the device format
      pub claim: Vec<u8>,              // the kernel's public arguments, at most cap::CLAIM (1 KiB)
      pub proof: Vec<u8>,
  }
  ```
  The claim is the kernel's public arguments, SCALE-encoded, its last 32
  bytes the binding: the stock `auth` kernel's `AuthClaim { map_root,
  scope, nullifier, binding }` (128 bytes), the stock `owner` kernel's
  `OwnerClaim { owner, binding }` (64), an actor kernel's its own.
- **The node's clock:** the API's `Time` request answers the node's time
  in milliseconds, a SCALE `u64` (a gateway's `GET /time`). A client reads
  it before it picks `expires_ms`, because the proof binds that value and
  a refused expiry costs a new proof. The answer is not signed: a relay
  that lies about it makes the client pick an expiry the node refuses,
  which costs a new proof and nothing more, since ingress checks the
  expiry against its own clock. The node's key, which clients pin, keeps
  its own request (a gateway's `GET /`).
- **The binding digest:**
  `b = BLAKE2b-256("vos/cred/binding/v1" ‖ space ‖ agent ‖ instance ‖ method ‖ program ‖ arguments ‖ nonce ‖ expires_ms)`:
  `space` the `SpaceId`'s 32 bytes; `agent`, `instance` and `method` 4
  little-endian bytes each; `program` the id of the kernel's program as
  32 bytes; `arguments` as the codec writes them (a `u32` little-endian
  length, then the bytes); `nonce` 16 bytes; `expires_ms` 8
  little-endian bytes. The claim's `binding` is `C(T(binding), W(b))`
  (`proving.md` §8). So a proof authorizes one call: one space, agent,
  instance and method, one program, one set of arguments, once, before
  `expires_ms`.
- **The guards,** from the handler's attribute into its
  `MethodSchema::credential`:
  - `#[msg(credential = Auth("login"))]` is
    `CredentialGuard::Auth { name, once: false }`, proven by the stock
    `auth` kernel. It admits `Anonymous` origins; `name`, 1–64 bytes, is
    the scope's.
  - `#[msg(credential = Owner)]` is `CredentialGuard::Owner`, proven by
    the stock `owner` kernel. It admits `Owner` origins; the handler debits the account the digest
    holds (`ctx.owner()`), at apply, as the account is then.
  - `#[msg(proven = k)]`, `k` one of the actor's own device kernels, is
    `CredentialGuard::Kernel { name }`. It admits `Kernel { program }`
    origins, `program` one of the kernel's window; the handler's first
    argument is the claim, decoded whole from its own part as the
    kernel's public arguments (`vos_sdk::device::Claim`), which it checks
    at apply (`light-node.md` §4); apply runs it only while the guard
    still names the kernel the proof is of (`CredentialedInput.kernel`).
    An actor's own kernel takes its name before a stock one's. With no
    own `auth`, `#[msg(proven = auth)]` is refused: the stock auth
    kernel's guard is `credential = Auth(..)`, which names its scope.
  - The stock kernels' checks (the auth scope, the root's ring and
    freshness, `once`) are the node's, in Rust, at ingress and at apply;
    an actor kernel's are its handler's, at apply.
  - Only a `&mut self` handler takes one, and no role or `linearizable`
    beside it, nor `credential` and `proven` together. A method without
    a guard refuses `Anonymous`, `Owner` and `Kernel` callers
    (`Failure::Forbidden`).
  - A stock guard needs its agent's credential actor (§6), whose
    release holds the stock kernels: installing a program with one into
    an agent without that actor fails `Failure::Credentials` (15).
  - **`once`** [decided]: `#[msg(credential = Auth("vote"), once)]`
    admits each nullifier once in its scope. The nullifier is a stable
    pseudonym, so the guard, not the handler, keeps the set: apply records
    the system row `once(scope ‖ nullifier) → t`, `t` the batch time of
    its admission, kept for good; the scope digest names the space, agent,
    instance and guard name, so the rows are scoped by construction. The
    row is written only when the handler returns `Ok`, in the apply that
    ran it [decided]: a refused ballot is not a cast vote, so a call
    the handler fails or refuses leaves the member free to try again,
    with a new proof (its `b` stays recorded). A repeat of an admitted
    nullifier is refused (`CredentialRefusal::Once` at ingress,
    `Refusal::Once` at apply). A new round takes a new name, so a new
    scope. `once` needs an `Auth` guard and is part of
    `CredentialGuard::Auth`. Each of a member's devices holds a secret of
    its own (`light-node.md` E2), so a leaf and a nullifier of its own:
    `once` admits a member **once a device** [decided], which the space's
    chrome states; a member with three devices votes three times. A
    device revoked and another enrolled is a fresh leaf and a fresh
    nullifier, so what bounds a person's admissions is the count of its
    enrollments (§6), not the devices it holds: its devices of a year,
    those it held as the year began and those it enrolled in it, at most
    its limit and `REPLACEMENTS` (2) [decided]. Periods are fixed blocks
    of batch time, so a person of limit 3 is admitted at most five times
    in a scope within one period, and at most nine (twice its limit and
    three) in one that spans a period's end: it may hold one device as the
    period ends and enroll its limit and one more in the next. One admission a person, a ring of
    person leaves, is later work (`open.md`).
- **Ingress's checks, in order,** each cheap one before any dearer, every
  state read on this replica's applied state; each refusal is
  `Rejected(Credential(code))` (index 9 of `Rejection`), `code` a
  `CredentialRefusal` of the index shown. Apply refuses under refine's
  `Refusal`, another enum; where both have a name (`Replayed`, `Once`),
  the text says which:

  | # | check | refusal | a gateway's HTTP |
  |---|---|---|---|
  | 1 | the frame within its kind's size | the frame error `Oversize` (not a credential code) | 413 |
  | 2 | it decodes, exactly | `Malformed` (not a credential code) | 400 |
  | 2a | an onion-only agent's: the gateway marked it onion (`node-api.md` §2–§3) | `Admission(OnionOnly)` (not a credential code) | 403 |
  | 3 | this node serves the agent | `NoAgent`, `Elsewhere`, as for calls | 404, 421 |
  | 4 | the node's space has a genesis (its `SpaceId` is not `NONE`) | `NoSpace`, 0 | 403 |
  | 5 | `format` is the device format, until its retirement (`light-node.md` §4.4) | `Format`, 1 | 403 |
  | 6 | `proof` within 1.5 MiB, `claim` within `cap::CLAIM`, `arguments` within `cap::REQUEST - cap::CLAIM` | `Size`, 2 | 403 |
  | 7 | `now ≤ expires_ms ≤ now + 120 s`, `now` the node's clock | `Expiry { now }`, 3 | 403 |
  | 8 | the instance's method exists and has a guard | `Method`, 4 | 403 |
  | 9 | the claim's shape is the guard's (auth 128 bytes, owner 64, an actor kernel's at least 32), and the guard's kernel has a window: the credential actor's for a stock kernel, the method's actor's for its own | `Kind`, 5 | 403 |
  | 10 | the window's programs are held, at least one computed | `Unavailable` while one is computed (retryable), else `Kind`, 5 | 503, 403 |
  | 11 | auth: the claim's `scope` is the one the guard's name gives | `Scope`, 6 | 403 |
  | 12 | the claim's `binding` is `C(T(binding), W(b))` of this request, `b` under one of the window's programs | `Binding`, 7 | 403 |
  | 13 | `b` is not recorded | `Replayed`, 8 | 409 |
  | 14 | auth with `once`: `(scope, nullifier)` not recorded | `Once`, 9 | 409 |
  | 15 | auth: `map_root` is in the credential actor's ring | `RootUnknown`, 10 (`RootRefusal::Unknown`): retryable, read the tree's feed again, or ask another replica; an honest member meets it on a replica's lag, a root a later write at its own batch time replaced (a trailing leader times each batch past the one before), or one past the ring's 64 entries (§6) | 503 |
  | 16 | auth: `map_root` is the ring's newest, or was superseded at most `ROOT_GRACE_MS` before the node's clock | `RootStale`, 11 | 403 |
  | 17 | a verification slot is free: fewer verifications in flight than the node's budget (by default twice its executor threads) | `Busy` (not a credential code) | 503 |
  | 18 | on an executor, the proof's interaction PoW holds over its leading fields before it is decoded; then it decodes and verifies under the program the binding names against `H_io` of the claim | `Proof`, 12 | 403 |

  Then the call goes to the agent's leader as `Input::Credentialed`,
  forwarded as a call is by a replica that does not lead, and its answer
  is `Ran { outcome, at }` once this replica has applied it, or apply's
  refusal under the same codes. `Proof` is one code for every failure, so
  a refusal says nothing of where a proof failed. There is no bucket per
  scope or method for an attacker to drain: the bounds are the node's
  connections and its verification budget.
- **The log carries** `Input::Credentialed` (index 10 of the batch's
  `Input`: the session-less kind, which anonymous inputs of a shared
  pool (§8) will also take), never the proof or the nonce, and the
  device format the proof was verified under, so that every replica, not
  only the one that verified it, judges whether the format is retired; a
  log entry grows by at most the claim's cap:

  ```rust
  pub struct CredentialedInput {
      pub origin: Principal,           // Anonymous, Owner or Kernel
      pub instance: InstanceId,
      pub method: MethodId,
      pub arguments: Vec<u8>,
      pub binding: [u8; 32],           // b
      pub expires_ms: u64,
      pub claim: Vec<u8>,              // the kernel's public arguments
      pub kernel: MethodId,            // the kernel the proof is of
      pub format: u32,                 // the device format verified under
  }
  ```
- **At apply** (refine, in the batch's order, at the batch's time `t`):
  1. `expires_ms < t`: refused, `Refusal::CredentialExpired` (7);
     after the binding's check (2), the device format one the release
     does not admit
     (`defaults::DEVICE_FORMATS`, 47 alone), or
     past its release's date or the date the agent's log retired it at
     (`Admin::RetireFormat`, the operator's `Retire::Format` for an
     agent, one call for each agent that takes proven calls): refused,
     `Refusal::Format` (11). A node's configuration
     narrows what its own ingress admits and never what the space
     runs: a replica admitting a retired format verifies its proofs for
     nothing [decided];
  2. `b` recorded: refused, `Refusal::Replayed` (8);
  3. auth: the claim's `map_root` neither the ring's newest nor
     superseded at most `ROOT_GRACE_MS` before the earlier of `t` and
     `expires_ms` less the 120 s horizon, the latest time an ingress could
     have admitted it (`credentials::judged_at`): refused,
     `Refusal::StaleRoot` (9);
  4. a `once` guard: `once(scope ‖ nullifier)` recorded: refused,
     `Refusal::Once` (10);
  5. `b` recorded, the system row `binding(b) → expires_ms`, collected by
     the sweep at `expires_ms` plus 60 s through the bindings' due index
     (the sweep's step lists the bindings it forgets beside its sessions,
     64 at most);
  6. the method runs, its caller the origin, under its guard, an actor
     kernel's handler on the claim then the arguments; whatever it
     returns, `b` stays recorded (`Failure::Forbidden` or a trap consumes
     the input);
  7. a `once` guard: the row `once(scope ‖ nullifier) → t` recorded only
     if the method returned `Ok`, in this apply, beside its writes
     [decided].

  A batch runs at most 64 proven calls (`defaults::BATCH_CREDENTIALED`):
  the first past them cuts it short, and the leader holds the rest for
  the next, so the sweeps forget bindings as fast as batches record them.
  A refused input writes nothing. So a proof replayed at another replica
  runs once, and a revocation binds every replica at the same batch. A
  duplicate is answered `Refusal::Replayed` at apply (or
  `CredentialRefusal::Replayed` at an ingress that has applied the
  first), without the first call's outcome [decided]: a client that
  lost its answer reads state (a balance, a record). A replica's own
  resend of a call it forwards (after a lost answer, or a leader
  change) is no duplicate: each log entry carries, beside its work
  result and under no proof, the origin of each proven input, the
  replica that took it at its ingress and its forward's token. When a
  later send is refused `Replayed`, or `CredentialExpired` after the
  call's expiry passed under a resend, and the replica applied the run
  of an entry naming it and that token, its client is answered that run.
  Any other copy (another replica's, another client's) is answered
  `Replayed`, and so is the replica's own resend when a snapshot, not
  the entry, brought it the run.
- **On JAM,** an agent whose builder is one of the space's nodes takes a
  proven input as it takes any: its builder's ingress verified the
  proof, under the trust-boundary rule above.
- **The kernel's program** is one the node computes from a release of
  the installed kernel, on the public statement its reference program
  returns [decided], so every node and the device's release build
  compute one program from the kernel: the leader at the install, which
  fails for a device kernel whose reference does not run; a replica that
  did not install it, once, at the first proof naming the kernel that
  passes the checks before the binding. The guard admits its kernel's
  release and, until its date, the previous one (`light-node.md` §4.4);
  the binding names which.

**Guards are the same on VOS and on JAM.** Inside a space the evidence is
signatures and grants, checked at ingress. Across the boundary the
origin is the sending service or space, and the authority is a proof
(§10).

## 6. Identity in a space

- **The identity agent:** a system agent per space.
  - **An identity's id** is the hash of its creation record, as agent ids
    are, never a key.
  - **It holds** a set of authenticators with a policy (any one device, a
    threshold, one device within limits), revocation epochs, and
    recovery.
- **Every node holds a replica of the identity agent** [decided]:
  - ingress reads its applied state locally to resolve a device to its
    identity and epochs, with no round trip;
  - a revocation reaches every node within replication lag and is
    checked on every request, not only when a session opens;
  - ingress keeps working while the identity agent's leader is
    unreachable.
- **The replica's contract:**
  - **Its shape.** Not every node is a voter: quorum and commit latency
    would grow with the space, and vos-raft has only voters today. A
    node outside the quorum holds a read-only follower: a snapshot,
    then the log's tail. That is either a non-voting role added to
    vos-raft, or the identity agent's applied state shipped to
    non-members; it is chosen when the replica is built (`open.md`).
  - **Bootstrap.** A node serves ingress only once its replica has
    applied a snapshot no older than the leader's commit at its join.
    Until then it forwards the request (`PeerMessage::Forward`) or
    refuses with "warming up". It never resolves against an empty
    table.
  - **Lag, unknown devices.** A device registered or re-enabled
    recently can be unknown to a lagging replica. It is refused with a
    retryable code, and the client retries elsewhere. The identity
    agent's own writes always go through its leader.
  - **Lag, revoked devices.** A device revoked recently is accepted
    within the lag. The log entry records the identity epoch ingress
    read, so the window is auditable.
  - **Linearizable epochs.** A method can declare in its schema that it
    needs a linearizable epoch, and ingress then reads it with
    `ReadIndex` against the identity leader. This is an ingress policy
    the schema names, not a guard: a guard cannot re-check another
    agent's state, and on JAM the witness covers only the agent's own
    keyspace.
  - **Monotone epochs.** A node never resolves against an epoch older
    than one it has applied, across restarts too. A replica reloading
    an older snapshot would otherwise re-admit a revoked device.
- **Authenticators:**
  - ed25519 keys, as today;
  - SSH keys, signing through an agent without exposing the key;
  - passkeys (WebAuthn, P-256);
  - hardware tokens.
  - Ingress verifies them all, so this needs signature checks at
    ingress, not precompiles inside guests.
- **Operators are identities too:** a node's key is bound to its
  operator's identity, so hosting and acting are two grants, never one
  key for both.
- **Operator requests** (creating agents and representatives, installs,
  replicas, roles, reports) [decided]: requests of the node's binary
  API, each signed by an operator key the node's config lists, with a
  nonce and an expiry as a call's; the node records the nonce until the
  expiry and refuses an unlisted key, a replay or an expired request. A
  gateway, and s4's operator console in it, only relays them: the
  console's operator signs in their own client, so a relay keeps nothing
  it can reuse. The envelope (`Operated`) names the node it is signed
  for, its key, a nonce, an expiry within 120 s and the kind's body; the
  node records each write kind's nonce, synced before the command runs,
  and forgets it only past its expiry and the 120 s horizon; every
  operator kind is signed on every transport, the socket included
  (`node-api.md` §4). The node makes `operator.key` at its first start
  and lists its public half unless told not to, so the CLI on its host
  signs as an operator.
- **Registration of identities** is the space's choice: open
  self-registration, invitation (onboarding tokens), or
  a governance decision.

**The credential actor** [decided; its tree is `proving.md`
§8's]: `vos-credentials`, a library actor installed in the agent whose
methods it guards. A guard reads only its own agent's state, so a
credential guards the methods of the agent its actor lives in; credentials
across a space's agents wait for the identity agent above.
- **One an agent:** its program's schema marks it the credential actor
  (`#[actor(credentials)]`); its install writes the system row
  `credentials → instance`, and the install of a second, at another
  instance, fails `Failure::Credentials`. Ingress and refine find it there.
- **Its install** takes the space's **handle**: 32 bytes the founder draws
  once and keeps across re-foundings, so members' device secrets survive
  one [decided]. It is public: the app shows it and pins it at a
  member's first enrollment. The actor takes it by `found(handle)`, role
  `registrar`, once and never zeros, which also writes the ring's first
  root; it takes no other write before.
- **Its rows,** the instance's tables, each tagged
  `derive_id("vos/table/", name)`, plain rows (not committed: no venue
  reads them):
  - `slots`: a `member` digest → its slot, a `u32`;
  - `nodes`: `(level, index)` (one byte, then 4 big-endian bytes) → a
    digest, kept only when not the empty subtree's; level 0 holds the
    leaves;
  - `free`: freed slots, keyed by their 4 big-endian bytes in an ordered
    table, so the lowest is reused first;
  - `invites`: a `member` digest → its invitation's expiry, in
    milliseconds of batch time;
  - `ring`: one row, the last 64 roots, newest last, each `(root, since)`:
    a root and the batch time it became the tree's root;
  - `opening`: one row once the registrar opened the open claim, its
    terms, its salts' seed, and the current period with its count;
  - `persons`: a person's id, a `u32` → its record: its limit and each
    device's `member` and `owner` digests, the first the one the registrar
    registered;
  - `owners`: a confirmed device's `owner` digest → its person's id;
    `pending`: an enrolled device's `owner` digest awaiting its own proof
    → its person's id; `devices`: a device's `member` digest → its
    person's id;
  - `people`: one row, the persons ever registered, the next one's id;
  - its struct: `handle`, `next` (the lowest slot never used) and `count`
    (the members enrolled).
- **The ring:** a write whose batch time equals the newest entry's
  `since` replaces that entry's root; any other appends an entry, dropping
  the oldest past 64; the install writes the empty tree's root. A root is
  **accepted** while it is the newest, and for `ROOT_GRACE_MS`
  (90 s, two of the device feed timer's longest gaps, `light-node.md`
  §6.7; `vos_wire::defaults`; not the venues' `MaxRootAge`) after the
  next entry's `since`, the moment it was superseded. Ingress measures
  that by the node's clock, apply by the earlier of the batch's time and
  the call's expiry less the 120 s horizon, so apply never refuses what
  an ingress admitted (§5). So a revocation binds every replica within
  the grace and the horizon of its batch, and an honest ingress within the
  grace; and an honest member's path stays good for as long after any
  change to the tree, which its feed's timer shows it well within. A
  gateway that holds the feed back marks a device's root for the grace
  alone. The 64 entries bound storage, and in a busy space freshness too:
  a root that has fallen out is `RootUnknown`, so 64 tree-changing batches
  within the grace make an honest root unknown before it is stale.
  `RootUnknown` is retryable by reading the feed again, and the device
  library reads it well within 64 batches' time: its timer's period is
  well under the time the space takes to make 64 tree-changing batches,
  not merely under the grace (§7).
- **Its methods:**
  - `enroll(member) → slot`, role `registrar`: the lowest free slot, else
    `next`; refused for a member enrolled;
  - `enroll_many(members)`, role `registrar`, at most 256 a call, at the
    lowest slots never used: the re-founding runbook's re-seed, into a
    tree with no freed slot (fresh slots are contiguous, so 256 fit one
    handler's gas wherever slots were freed);
  - `invite(member, expires_ms)`, role `registrar`, and `claim(member)`,
    any caller: an invited member enrolls itself until the expiry, a claim
    at `expires_ms` included. An expired invitation stays until a
    `revoke` withdraws it or a new `invite` replaces it. The
    invitation names the digest, so whoever intercepts the claim cannot
    enroll another (the ledger's accounts take the same two steps,
    `Payments`' `invite` and `open`). A member with
    no client key of its own has its claim sent by the app that serves it
    (the demo's gateway app, under its own client key): an ordinary
    client's authority, bounded by the invitation, which names the
    digest;
  - `open(difficulty, cap, period_ms)`, role `registrar`, and
    `claim_open(member, nonce)`, any caller: the open claim of a space
    that admits anyone, a home-only space (`light-node.md` §3.3). A
    member enrolls itself when `BLAKE2b-256("vos/cred/open/work" ‖ handle
    ‖ member ‖ salt ‖ nonce)` starts with `difficulty` zero bits (at most
    64), at most `cap` members a period of `period_ms` of batch time
    (`Cap` past it, a cap of 0 closing it, `Closed`). The salt is the
    period's, `BLAKE2b-256("vos/cred/open/salt" ‖ seed ‖ period)`, from a
    seed the actor draws at its first opening, which no query answers
    (its replicas and operators hold it); the
    period's salt and the one before are accepted, so work made just
    before a period ends still counts, and none is made before its
    period's salt is served. A re-opening keeps the period's count only
    for the same period and length. `opening()` answers the salt, the
    difficulty, the period, the cap and the claims the period takes yet
    (the `opening` row);
  - `revoke(member)`, role `registrar`: the leaf back to the empty leaf,
    the slot freed; for a member only invited, the invitation withdrawn;
    either way the member dropped from its person, and the person with it
    once it holds no device;
  - **persons** (`light-node.md` §3.8): each device of a member derives
    its own secret, so its own `member` and `owner` digests, which nothing
    links; the registrar, which knows both digests of a member it enrolls
    or invites, links them:
    - `register(member, owner, limit)`, role `registrar`: a member
      enrolled or invited (an invitation past its expiry `Expired`), and
      its owner digest, the first device of a person of at most `limit`
      devices (1 to `MAX_DEVICES`, 16); refused for a member or an owner
      digest a person holds (`Held`); an owner digest only awaiting its
      confirmation gives way, the registrar's word the binding one;
    - `limit(member, limit)`, role `registrar`: the limit of `member`'s
      person; devices past it stay, and the person enrolls none until it
      is below;
    - **the enrollment count** [decided]: a person's devices of the
      enrollment period (`ENROLLMENT_PERIOD_MS`, a year of batch time,
      the span between a home's re-proofs), those it held as the period
      began and those it enrolled in it, are at most its limit and
      `REPLACEMENTS` (2), past which `enroll_device` is refused
      (`Enrollments`); `reset(member)`, role `registrar`, starts the count
      again from the devices the person holds. The year and the two follow
      the design's own numbers: a phone is retired every few years
      (`light-node.md` §3.8), so two replacements a year cover a retired
      phone and a lost one with room to spare, and a third goes through the
      registrar's ordinary process, as a lost last phone does. Without it,
      revoking a device and enrolling another gives a person a fresh
      nullifier at each round, so a `once` guard admits it without bound
      and a home that is the user's own space hands it a pooled agent at
      each round;
    - `revoke_person(member)`, role `registrar`: every device of
      `member`'s person revoked, as `revoke` revokes one, in one tree
      write, and the person with them (`NoPerson` for a member of none):
      the expulsion, which no device of the person outruns, as it would
      a revocation of one device at a time by enrolling another while the
      person is under its limit;
    - `enroll_device(member, owner) → slot`, under
      `#[msg(credential = Owner)]`: the caller's confirmed owner digest
      names its person (`NoPerson` for none), which enrolls `member` as a
      device within its limit (`Limit`); its leaf proves at once. The
      digests are the caller's word, so a member enrolled (`Enrolled`) or
      invited (`Invited`: the registrar named it for its own claim), and
      a member or an owner digest a person holds or awaits (`Held`), are
      refused; and `owner` acts for the person only once its own proof
      confirms it, so a person cannot take another's owner digest, public
      in the ledger's log, and with it that member's later enrollments. An
      owner digest awaits its confirmation for `CONFIRM_MS` (a day): past
      it, another enrollment naming the digest takes it, so a person that
      names another member's digest for a device of its own holds it from
      that member's own person a day at most, each such hold spending one
      of its enrollments;
    - `confirm_device(member)`, under `#[msg(credential = Owner)]`: the
      added device's own proof, its owner digest awaited beside `member`,
      its own member digest, in the awaiting person (`NoPerson` for none),
      confirmed, so an enrollment that took a late digest for another
      member joins the device to no person; the pairing's one more prompt a space (`light-node.md`
      §3.8);
    - `revoke_device(member)`, under `#[msg(credential = Owner)]`: a
      device of the caller's person (`NotYours` for any other), the
      caller's own included, revoked as `revoke` revokes it;
    - no query answers a person; the registrar and the space's operators,
      who read the rows and the calls' digests, link a person's devices
      (`light-node.md` §8.8 L7). A space whose members pay each
      other's devices links their owner digests in the ledger's log
      anyway (L4). A re-founding's `enroll_many` re-seeds members, not
      persons: the registrar registers them again;
  - queries, any caller: `feed(from) → Feed`, the tree's writes from the
    `from`th on, each the leaves it set and the root it left with its
    batch time, a page at most 48 KiB, and the feed's length, from which a
    device keeps the whole tree and computes its own path
    (`light-node.md` §6.7); `path(member) → Option<(root, slot,
    siblings)>`, the 32 siblings from the leaf's level up; `root() →
    (root, since)`;
    `handle() → [u8; 32]`; `count()`, the members enrolled. A query is
    signed by a client key like any other; the device library signs each
    with a key drawn for it alone.
- **Its cost:** 33 calls of `0x402` an enrollment (32 a revocation, whose
  leaf is the empty one; an `enroll_many` shares the nodes its members
  have in common), each 3,000 gas to the actor. The VOS host serves it
  natively and a JAM-deployed agent through the shim's software
  permutation (about 37,600 gas), so the tree is a function of its writes
  on both. The rows dominate: an enrollment costs the actor about 4.1M
  gas, a revocation 4.1M, an `enroll_many` of 256 fresh slots 78M of the
  100M a handler may request [measured].
- **Built:** `vos-credentials` (`agent/credentials`), `#[actor(credentials)]`;
  the tree's values, the ring and its freshness rule in
  `vos_wire::credentials` (`Ring::accepts`, `RootRefusal::{Unknown,
  Stale}`, `credentials::judged_at`, `defaults::ROOT_GRACE_MS`), which
  ingress, apply and the device library share; a reference built from `proving.md` §8 alone equals the
  actor's tree over random enrollments and revocations, on a VOS host and
  on the JAM-only host [measured].
- **Re-founding:** a space that changes venue, or whose anchors
  equivocated, ends and founds again under a new `SpaceId` (§11); its
  sovereign funds leave by its controller and its Clerk pairs reset. The
  re-founding runbook installs the new space's credential actor with the
  ended space's handle and re-seeds it with `enroll_many` from the ended
  space's `member` digests, with no member action. Slots may move, and a
  member's device reads the new space's feed.

## 7. Credentials: facts proven about oneself

**What it is:**
- An actor in one space attests a fact about one of its identities as a
  committed attestation. The leaf sits under the issuer's committed root.
- The holder proves the fact to another space, or to JAM, in zero
  knowledge against the issuer's anchored root (§11). It reveals neither
  the identity nor anything beyond the fact.
- A Kreivo pass becomes a credential proven against Kreivo's state.

**Which first** [decided]:
1. **membership:** "a member of S since T, not revoked". It powers the
   anonymous origin (§5) and is the migration path for Kreivo pass
   holders. Its in-space form, with ownership beside it, is built first
   (below);
2. **solvency:** "balance at least Y", from a Clerk ledger;
3. **reputation thresholds,** once a space keeps reputation.

**Pitfalls to design for:**
- **The issuer gives the holder the leaf's salt and path.** Salts derive
  from a version's seed the holder never sees (core model §9.3).
- **Timing links:** a credential issued in A and proven in B within one
  window links by time, so proofs should wait or batch.
- **A nullifier is scoped:** one pseudonym a scope, never global, or it
  becomes the global handle §1 rules out. A method that admits a
  member once a scope takes the `once` guard (§5), which keeps the
  nullifiers it has admitted.
- **Across spaces, a leaf is keyed by the identity and its revocation
  epoch,** so an identity revoked in A cannot keep proving old facts in
  B.
- **Freshness:** a verifier demands a root within N windows, and the
  issuer drops a revoked leaf, so a credential lapses within N windows
  of its revocation.
- **Fetching paths leaks timing.** A holder needs a fresh path every
  window, and asking the issuing space for one on demand tells the
  issuer when the holder proves. So the holder syncs the committed map
  its leaf sits in (the syncing axis, §9), or fetches paths
  anonymously.

**In a space first** [decided]: the first credentials are proven
to their own space's ingress, not across spaces. Membership (auth) proves
a leaf of the space's credential actor (§6) and yields an `Anonymous`
origin; ownership (owner) proves the secret behind an account's owner digest
and yields an `Owner` origin (§5). Their stock kernels, words and format are
`proving.md` §8's. Across spaces the pitfalls above hold as written; in a
space three of them take a simpler form:
- **No epoch in the leaf** (`member = C(T(member), s)`): revocation removes
  the leaf, and the device could neither keep an epoch nor the actor check
  one.
- **Freshness is time, not windows:** a root is accepted for
  `ROOT_GRACE_MS` after it was superseded (§6).
- **The scope carries the space:**
  `scope = C(T(scope), W(BLAKE2b-256("vos/cred/scope/v1" ‖ space ‖ agent ‖ instance ‖ name)))`,
  the agent and the instance four little-endian bytes each, `name` in
  SCALE (a `u32` little-endian length, then its bytes, `proving.md` §8);
  so no two agents' guards of one name, in one space or two, share a
  pseudonym, even for a member whose secret two spaces share.
- **The nullifier** is `C(C(T(nf), s), scope)`: a value only the holder
  of `s` computes, stable in its scope (a pseudonym, not a one-time
  token), unlinkable across scopes and to `member` or `owner`. A method
  that admits it once takes the `once` guard (§5).

**The device secret** [decided; built, `vos-light`]: the
member's `s` comes from a secret source, a keyed HMAC-SHA-256 whose key
the device never exports, evaluated once a use after the user's consent
(`proving.md` §8 pins it):
- **the input:** `input = SHA-256("vos/device/input/v1" ‖ handle)`, the
  message the source's HMAC takes, `handle` the space's stable 32-byte
  handle (§6), not its `SpaceId`, so a member's secret survives a
  re-founding;
- **the derivation:** `o` the source's 32-byte output;
  `w = BLAKE2b-512("vos/device/secret/v1" ‖ handle ‖ o)`;
  `s_i = u64_le(w[8i..8i+8]) mod p` for `i < 8`; derived again at each
  use, never stored; `member(s) = C(T(member), s)` goes to the credential
  actor, `owner(s) = C(T(owner), s)` to a ledger account;
- **the sources** [decided]: by default an Android Keystore HMAC key
  (non-exportable, user authentication by a biometric or the PIN at every
  use through `BiometricPrompt` with the `Mac` as its crypto object,
  StrongBox-backed when the phone has it, Android 11 or later), its
  output a `byte[]` zero-filled once copied; optionally a security key's
  `hmac-secret` by CTAP2 directly through YubiKit, over USB or NFC,
  always with user verification (its PIN) and a touch, one credential for
  every handle under the pinned `rpId` `"vos.device"`. No passkeys,
  Credential Manager or Play services; a source that spans devices is
  later work. The device keeps only the source's reference (the Keystore
  alias, or the security key's credential id) beside what enrollment
  pinned.

**The device side, as built:**
- **The device library** (`vos-light`, `proving.md` §8): it derives `s`,
  computes the scope and the binding (`vos_wire`'s functions, the ones
  ingress calls), proves auth, owner and device-kernel statements, and
  builds every node-API request and decodes every answer, so neither the
  client nor a gateway encodes a credential's bytes. Its `TreeKeeper`
  keeps the whole tree from the actor's feed, each page checked against
  the root its last change names, on a jittered timer of its own, and
  computes the member's path, so no query names the member (`light-node.md` §6.7):
  on a 30 s timer jittered by half a period either way, a `RootUnknown`
  bringing the read forward to a time drawn below 10 s and halving the
  period (to 1 s), a read that finds the tree unchanged doubling it back.
  Its queries are signed by a key drawn for each. Its `SECURITY.md`
  states the secret's containment.
- **The `vos.credential` facility** [decided]: a client
  facility of s4's Android client (VOS's `node/light/android`), called by a server's document and
  gated by the client's grant, implemented in Rust over `vos-light` (a
  library the client loads), unsupported below Android 11. Its
  operations:
  - `enroll`: the space, its handle, the agents and their identities, the
    guarded methods, their guards and scope names, and the ledger's
    `transfer`, shown in the client's trusted chrome and **pinned**; the
    source's key made, `s` derived, `member(s)` and `owner(s)` shown in
    the device's own chrome. A later request naming another space,
    handle, agent or method is refused, as is an enrollment for a handle
    or space another origin holds;
  - `sign_in`: a pinned method's auth proof; the chrome names the method
    and, for a `once` guard, that the call spends the member's one
    admission in its scope, so a server cannot pass a vote off as a
    sign-in;
  - `pay`: an owner proof of `transfer(from, to, amount)` encoded from the
    facility's own chrome form, which the server's request only
    pre-fills and the member may edit [decided], so the binding
    covers what the member saw;
  - the grant (per connection) and a call's confirmation (per call, a
    form answering only after 600 ms on screen) are two prompts.
- **Its transport:** the gateway's credential surface takes an ephemeral
  SSH key drawn per connection, as no one in particular, with no resume
  and no remembered grant; the gateway's host key is pinned as for any
  host. Paths and the node's time come over the gateway's `vos-api` SSH
  subsystem on connections of their own, each under a fresh key [decided]; a path is used only when its root is one the root polls saw; a
  node time more than five minutes from the device's is refused.
- **Claims:** a member here has no VOS client key, so the gateway's s4
  app sends `claim(member)` and the ledger's `open` under its own
  client key, its authority the operator's invitations, which name the
  digests.

**The in-space credential's threat model:**
- **Whom it protects against:** outsiders and the space's other members,
  not its operators. The log carries the origin ingress derived, never the
  proof (§5), so an operator can log an `Anonymous` or `Owner` origin it
  never verified, as it could run any call; members trust their space's
  nodes for integrity, as every cell of §3 does. A space that wants
  evidence turns on the non-repudiation side store, which keeps the
  proofs.
- **The device secret's containment, as it is** (its sources are
  `proving.md` §8's [decided]):
  - `s` lives in the library, zeroized on drop. Its source's key never
    leaves the Keystore (or the security key), but the source's output
    `o`, from which anyone holding the public handle derives `s`, crosses
    into the app's process at each use: a `byte[]` from `Mac.doFinal` (or
    YubiKit's answer), which the bridge zero-fills and the library
    zeroizes once copied.
  - Code in the app's process during a use (a compromised dependency, a
    debugger on a debuggable build, a rooted phone) reads `o`, and with it
    `s` for good.
  - The key is bound to the phone (or to the security key), not to an
    account: nothing syncs it, and no restore elsewhere derives `s`. Its
    loss (a factory reset, the screen lock removed, a lost security key)
    loses `s`: the member is revoked and enrolls again, and the ledger's
    `rekey` moves its account.
  - Each use takes the user's consent at the source (a biometric or the
    PIN at the Keystore; the PIN and a touch at a security key), so
    malware cannot evaluate it silently; one use is enough to keep `s`.
  - What `s` gives a thief: auth as its member in every scope of the space
    (and of every space sharing its handle), payment from the account
    `owner(s)` holds, and every nullifier the member has used or will use,
    so the member's past pseudonyms link to it. Revoking the leaf stops
    auth within `ROOT_GRACE_MS` and the 120 s horizon; it does not stop
    payment, which reads no tree: the ledger's `rekey(account, owner)` and `freeze(account)`,
    under an operator role, do [decided].
  - **The in-space ledger is custodial by design:** an operator who can
    `rekey` can move any account to a key of its choosing. It is the tier
    such a space picks [decided]; the log attributes each `rekey` to
    the operator's origin, so the power is visible, not hidden. A space
    that refuses custody waits for full privacy's pool (§8).
- **Replay** is bound by the binding digest (§5): another space (its
  `SpaceId`), another agent, instance or method, other arguments or
  another statement each change `b`, so the proof fails ingress's
  `Binding` check; a proof is good for 120 s at most, and its `b` is
  recorded at apply until it expires, so it runs once across every replica
  of the agent; a re-founded space has a new `SpaceId`, so no proof made
  for the ended one authorizes anything in it. A proof intercepted in
  flight can be sent by the interceptor before its owner: it is the same
  call, run once. The transports keep it from on-path observers (the node
  API's QUIC, a gateway's TLS or SSH); a gateway sees every proof it
  relays and can do the same, and nothing more: it holds no authority.
  The node's `Time` is unsigned; a relay that lies about it costs a
  client a new proof, and cannot extend a proof's life past the 120 s
  ingress allows by its own clock.
- **Revocation** binds every replica within `ROOT_GRACE_MS` and the
  120 s horizon (3.5 minutes) of the revoking batch, by batch time (§5's
  apply rule), and an honest ingress within the grace: a revoked member's
  proof against an older root is refused then, whatever a lagging
  replica's ingress accepted. Within the window a revoked member can still
  authenticate.
- **What operators learn:**
  - from the tree's feed: nothing of the member's. The device library
    keeps the whole tree from `feed(from)`, whose query names only its
    place in the feed, read on a timer of its own (never just before a
    proof, but for a device's first sign-in, which waits for its leaf
    reading the feed: `light-node.md` §6.2), and computes the member's path itself (`light-node.md` §6.7);
  - from each request's address and timing: a proof's connection shows
    the node or gateway that serves it where it came from and when, which
    links its nullifier to that address. So `Anonymous` hides the member
    from the log's readers, other agents and other members, not from the
    operators of the nodes and gateways that serve its requests; that is
    full privacy's (§3, §8);
  - from the log: each auth call's scope and nullifier (a pseudonym's
    activity in one scope), each payment's owner digest (a public payer),
    each credentialed call's arguments in clear (a payment's payee
    and amount beside its payer), and the metadata every cell leaks (§3);
  - from the root each auth call names (in its claim, logged for the
    apply's freshness check): a device on the feed proves against the
    newest root it has read, the one every member who read the feed since
    a tree change holds, so the roots logged link nothing beyond the time,
    except for the members who prove within a timer period of a change
    before reading it. The log keeps the root, not its place in the ring:
    a place relative to the newest moves between ingress and apply, and
    one counted from the first root names the root as its digest does;
  - from a tree change: a device reads the change as every member does,
    naming no digest;
  - from the tree: how many members there are and when each was enrolled
    or revoked (the feed serves every write and its batch time, to any
    caller); a leaf hides its digest from one who does not know it, but
    whoever knows a digest computes its leaf and learns from the feed
    whether and since when it is enrolled;
  - from a copied handle: two spaces sharing a handle can link their
    common members' `member` and `owner` digests (their nullifiers stay
    apart).
- **Denial of service:** every check but the proof's costs microseconds
  and is checked first; the PoW precedes every decommitment; a budget
  bounds the verifications in flight; the request's decode and the
  verifiers are fuzzed. A credentialed body takes one of the node's 64
  large places until its proof is verified; a gateway holds its own
  until the node answers.
- **What the carrier audit checks** (`proving.md` A.5): the member's
  secret (its source's output, `w`, `s` and its words, the nullifier's
  key, their hashes, a device kernel's arguments) and a proof's masks in
  every carrier, and its place in the tree in every carrier that leaves
  but the path's own fetch, over the node API's socket and a gateway over
  QUIC; the device library's errors and `Debug`
  output; the phone bench's output; and the facility through its C ABI,
  its every freed heap block included. No leak was found in VOS.
- **Known gaps,** each stated where it lives:
  - `s` stays in freed memory inside the prover: the recursion
    `Context`'s copy, the traces and the prover's polynomials, until
    reused (`node/light/SECURITY.md`);
  - copies outside the library's reach: YubiKit's, the Keystore's
    parcels, and the PIN's `Editable` in the client;
  - a secret source's failure text reaches the server as the platform
    wrote it (no secret in it, but the platform named);
  - the audit takes no needle of a small integer below 2^20 (a slot, a
    count);
  - the facility cannot forget an enrollment, and a cancelled call's
    form stays until answered (its proof dropped);
  - the demo's claim enrolls the member before it opens the account, so
    a wrong account name leaves a member with no account.

**Opt-in linking:** a holder can prove "the same person as identity X in
space A", and only to whom they choose.

## 8. Full privacy: personal spaces and a shielded pool

**The shielded pool is postponed** [decided]: the "hidden from the
operators, actor anonymous" cell, a tier each space opts into [decided].
The personal space is built as a personal agent at a home space and local
actors on the user's devices, and the network layer as Tor at the gateway
and the light node (`light-node.md` §3, §6). The pool's design, its
integrity without trusting its host and one pool shared by many spaces are
`open.md`'s ("Private payments (P2)", "Full privacy").

## 9. Membership, as axes

- **Hosting:** runs a node in the consensus of some agents, granted per
  agent; placement already uses it.
- **Syncing:** a light node or device replicating some agents, or some
  Merge scopes, for reading and local use. It needs read authority per
  agent or scope, never write.
- **Using:** acts on actors through any node, with no node of its own.
- **Guests:** public methods only.

Hosting grants no application authority: an operator can stop serving
an agent, but approving a payment is a member's grant like any other.

## 10. VOS and JAM: origins carried by their transport

**One rule:** an input's origin is what its transport authenticates.
- **Within a space:** the log and the placement, as today.
- **From a space to JAM:** the chain authenticates the sending service,
  the space's representative agent. Its authority is a proof.
- **From JAM to a space:**
  - a JAM agent's outbox is public state;
  - the space reads it through a JAM light client, with proofs of
    inclusion against JAM's state root, and the input enters with the
    origin `Jam { service }`;
  - **the light client** (header finality tracking) is a design of its
    own, not built (`open.md`).
- **Guards are the same on both sides:**
  - a VOS actor can require an input from a given JAM service;
  - a JAM agent can require one from a registered space's
    representative, carrying a valid proof.
- Crossing the boundary is a message, never a synchronous call. JAM's
  hops take blocks.

## 11. Anchors: the root chain, per space

- **The ordered root sequence** is JAM mode's root chain,
  in which each package's accumulate swaps one root for the next, in
  order. A space cannot prove two transitions from one root
  to two parties.
- **A root for the space,** not just for each agent:
  - a space has many agents, each with its committed root;
  - its representative agent keeps a space-level root over its agents'
    roots, per window: a committed map keyed `(agent, kind, w)`, the
    value an agent's root at its cut of w, itself cut at `B_w + D` (the
    window's boundary plus a close delay of `min(L/5, 2 min)`); the space
    root is `S_w = BLAKE2b-256("vos/space/v1" ‖ space ‖ w ‖ A_rep)`, over
    the representative's agent root at that cut (`proving.md` §7).
- **Windows** run at a fixed cadence, minutes apart. A root that moved
  only on activity would leak activity. They are Unix time from the
  space's genesis, whose hash is the `SpaceId` and which freezes the
  clock: `w = ⌊(t − origin)/length⌋`, the length per space in [2, 60]
  minutes, default 10.
- **What an anchor gives an outsider:**
  - the representative's leader signs the anchor with one registered
    node key and submits it to the space's one anchor venue: on Kreivo
    through the node's own sr25519 authority account, the space's
    sovereign account paying (`spaces-pallet.md`; a budget per window
    bounds what a compromised node key can spend); or the JAM statements
    service. A node reaches its venue through a `VenueClient`, which an
    extension will provide: the Kreivo client is built against a mock of
    the designed pallet, its chain transport a port of the Substrate
    extension once the pallet and the extension host exist; the JAM
    client is development tooling (`tools/jam-dev`), the node knowing no
    JAM. The anchor's signer is checked against the node keys the
    space's controller lists at the venue; a node's key is its only
    anchor key, so a compromised key means replacing the node [decided]. A leader the venue does not list hands its leadership to a
    replica it does. The anchor gives outsiders ordering;
  - two anchors of one window under different roots are an
    equivocation, and end the space for good: its roots
    refused, no resume, the record a tombstone; the space founds again
    under a new `SpaceId`, its credential actor installed with the same
    handle and re-seeded from the ended space's `member` digests [decided];
  - **no migration:** a space anchors at one venue for good; one that
    changes venue founds again [decided] (`proving.md` §7);
  - integrity comes only from a proof that names the anchor.
- **A venue anchors only a window its own clock has closed;** every
  deadline between parties is the venue's time.
- **Cost:**
  - on Kreivo an anchor is a ~170-byte extrinsic, a statement about 4 ms
    of ref_time unmasked [measured] and about 0.43 UNITS of length fee,
    plus a refundable deposit, all paid by the space's sovereign account;
    on JAM a statement is about 80M gas of refine;
  - "this root is in the sequence" is a witnessed read in the
    representative agent's state, which JAM mode's witnessed reads make
    cheap: on JAM,
    later; on Kreivo the pallet stores the anchors.
- **Statements disclose only their return value:**
  - "this window's net settlement with space B is X";
  - "this account's balance is at least Y";
  - "a member of set S, once in this scope".
- **Zero-knowledge masking is required by the first tier, not only the
  private one.**
  - An unmasked STARK opens parts of its trace, so a settlement proof
    sent to JAM would leak the space's ledger to the world.
  - The final proof is masked (format 39), over the recursion's one
    proof a run and a fixed shape per kernel.

## 12. The root space and the registry of spaces

- **Kreivo's `pallet-spaces`** (`spaces-pallet.md`, built by the Kreivo
  teammate, to replace pallet-communities later) holds the first
  registry: spaces registered from their genesis, each with a sovereign
  account and a map of its authorities, formats and programs with a
  7-day delay under the Virto community; the JAM statements service
  holds its own; a JAM registry agent comes later.
- **A registry agent on JAM,** public:
  - spaces register a name, their representative agent and their policy
    declaration;
  - **registration is pseudonymous:** it reveals a space's
    representative, never its members;
  - it records fees and a refundable deposit, which also answer spam;
  - it holds what spaces must agree on: the transpiler versions and
    verifier hashes accepted.
- **A change to accepted versions takes effect after a delay,** so a
  space can leave before an upgrade binds it.
- **Who governs it:**
  - at launch, the root space (Virto), as a DAO of its members, under a
    published charter;
  - later, a collective of registered spaces, each voting through its
    representative;
  - the charter names the triggers for the handover: for example N
    independent spaces active for M months, or a share of fees from
    spaces other than Virto above X, plus a sunset date.
- **A space's own keys** (its builder's signing key, behind
  `package::identity(service)`) rotate by a governance decision applied
  in accumulate; on Kreivo, the controller (an `AccountId`) lists and
  delists the authorities and the node keys the venue accepts.
- **Exit and disputes** need rules, not yet designed. A space's name on
  exit is released only after its deposit's delay, so exit cannot be
  used to squat.
- **Policy stays mechanical:** fees, names, accepted versions, disputes.
  It never reaches into a space's internals.

## 13. cipher-clerk

The Clerk's ledger kernel is cipher-clerk, a plain double-entry kernel
whose tests are its specification:
- **An entry's currency and ledger are its account's,** checked at
  apply, so no debtor converts currencies on its own signature.
- **The shape a VOS agent needs:**
  - plain integer amounts (`Value(u64)`, behind a seam a confidential
    value may later fill);
  - authority from ingress, per event, instead of signatures in the
    kernel;
  - explicit encodings, with version bytes, domain tags and pinned
    vectors;
  - no roots of its own;
  - settlement as a pure function whose output names both spaces, the
    window and a sequence.
- **No private tier:** the note model is redesigned on paper and
  reviewed before any private-tier code; it follows §8 and is postponed
  with it.

## 14. Design choices

- **The trust boundary, per executor** (§5): a space verifies at
  ingress, so guests never verify signatures and every replica and
  witness evaluates the same logged bytes; a public JAM agent, whose
  builder is anyone, takes only chain-authenticated origins and proofs;
  evidence is never logged, so members keep deniability, and
  non-repudiation is an ingress option, off by default.
- **The origin ABI with fixed codec indexes** (§5): `Client`, `Agent`,
  `Instance`, `Anonymous` and `Owner` built, `Identity` and `Jam`
  reserved, so their arrival changes no encoding; a session-less input
  kind, `Credentialed`, beside requests in a session.
- **One attestation primitive,** in clear or committed, the issuer
  choosing at issue, so a grant that never leaves the space pays nothing
  for anchoring (§5).
- **Two axes and primitives per cell;** each space chooses its cells and
  its privacy tier (§3).
- **The identity agent replicated on every node** [decided; not built],
  so ingress resolves a device and checks its epoch on every request with
  no round trip; its replica's contract is bootstrap, two-sided lag,
  schema-declared linearizable epochs and monotone epochs (§6).
- **Epochs plus short expiries** (§5): one bump voids every earlier
  grant at one local read, and no revocation list crosses a space.
- **Credentials in a space first** (§6–§7): membership in the credential
  actor's own rows, under a stable handle so members' secrets survive a
  re-founding, and no epoch in the leaf, since revocation removes it;
  then solvency, across spaces.
- **A public payer:** an owner proof shows knowledge of the secret behind
  an account's owner digest, bound to the call; the payment debits the
  account that digest holds at apply.
- **A device proof authorizes exactly what an auth proof does,** and its
  program is computed by every node from the installed kernel (§5).
- **Revocation does not stop payment:** an owner proof reads no tree, so
  the ledger's `rekey` and `freeze`, under an operator role, stop a thief
  and recover a lost secret; the in-space ledger is custodial by design
  (§7).
- **Paths refreshed apart from proofs,** on a connection and a key of
  their own, so a fetch's time says nothing of a proof's (§7).
- **A duplicate answered `Replayed`,** without the first call's outcome:
  a client that lost its answer reads state (§5).
- **The `once` guard keeps the nullifier set,** not the handler, its row
  written only when the handler returns `Ok`: a refused ballot is not a
  cast vote (§5).
- **The node's binary API and a gateway with no authority;** operator
  requests signed for one node with a nonce and an expiry, so a relay
  keeps nothing it can reuse (§6, `node-api.md`).
- **Secret sources the device never exports** (§7): an Android Keystore
  HMAC key or a security key's `hmac-secret`, each taking the user's
  consent at every use; no passkeys, Credential Manager or Play services.
- **The facility's own confirmation form** (§7): the payee and the amount
  confirmed in the client's trusted chrome, the server's request only a
  pre-fill, so the binding covers what the member saw.
- **The registry** (§12): a charter with handover triggers, a delay on
  version changes, pseudonymous registration.
- **Who pays:**
  - a member acting in a space: the space, with rate limits per
    identity;
  - a JAM service's message: the sender pays JAM, and the receiver
    pays for its light client;
  - anonymous non-payments: rate-limiting nullifiers, one action per
    period per scope;
  - anonymous payments: a fee inside the proof;
  - registered spaces: a deposit plus fees.

What remains open, and what is not yet built, is in `open.md`.
