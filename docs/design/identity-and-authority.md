# Identity and authority

Draft 5 of a design run on who acts in a space, how a request proves
it, what each actor may do, and what anyone outside a space learns.
- Draft 2 adopted the owner's idea of personal spaces.
- Draft 3 folded a second opinion (Fable): two axes, one attestation
  primitive, ingress verifying, personal spaces as device runtimes, the
  anonymous sender's transport.
- **Draft 4 folds the owner's answers:**
  - the recommendations on draft 3's questions are taken, subject to
    the reviewer's check;
  - **VOS builds primitives, and each space chooses its privacy
    model** from them;
  - full privacy (a shared shielded pool, personal spaces, a relay
    layer such as Tor or Arti bundled in the node) is postponed;
  - the review of cipher-clerk is folded into §13.
- **Draft 5 folds the second opinion on draft 4** (Fable):
  - the trust-boundary rule per executor, a space or a public JAM agent;
  - the identity replica's consistency contract;
  - the input kinds and the full origin ABI reserved in the first build;
  - a size rule for authority sets;
  - the path-fetch leak of credentials.
- **The in-space credential** (§5–§7) carries slice 7's pins with the
  owner's S21–S25: the origins `Anonymous` and `Owner`, credentialed
  calls and their checks, the credential actor, and its threat model.

Tags as in the core model. **[decided]** marks the owner's answers;
the rest is still proposed.

## 1. What the owner asks for

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

## 2. What exists today

- **A caller is a principal:** a client's key or another agent.
- **Each agent keeps a table** from principals to role bytes, set by the
  operator's CLI, and a handler names the role it needs. A workflow's
  role is checked at its start.
- **Clients sign each request** with their key, inside a session the
  client names.
- **Ingress authenticates clients into principals,** and the agent
  receives the authenticated origin. Guests never check signatures
  (core model §5).
- **Nodes** have keys of their own, and a space's nodes trust each other:
  the trust model is crash faults only.
- **No identities, devices, delegation or anonymous callers.**

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
  The relay layer (§8) addresses it; spaces that need it opt in.
- **When each cell arrives:**
  - the first build delivers the top-left cell, and with the
    messenger, the bottom-left;
  - the anonymous column needs the membership credential, so it
    arrives with §15 step 3;
  - the bottom-right is postponed.

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

**The rule, as the core model will state it:**

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
(`vos_wire::ids::Principal`) with its codec index:
- `Client(key)`, 0: a client's ed25519 key, in a session it signs. The
  identity agent (§6) turns it into `Identity { id }`, a person or service
  in this space through a device, at index 5, reserved;
- `Agent(id)`, 1: another agent of this space;
- `Instance(id)`, 2: the calling instance of the same agent, for a nested
  call;
- `Anonymous { scope, nullifier }`, 3: an auth credential proof's. The
  sender knows the secret behind a member's leaf; `nullifier` is its
  pseudonym in `scope` (§7, `proving.md` §8), stable across its calls;
- `Owner(digest)`, 4: an owner credential proof's. The sender knows the
  secret behind `digest`, the owner a row names: a public payer
  [decided, S22];
- `Jam { service }`, at index 6, reserved: a JAM service, authenticated by
  the chain or a light client.

Each digest is 32 bytes, eight M31 words as little-endian `u32`s. No role
is ever granted to an `Anonymous` or `Owner` principal: a `Grant` naming
one is `Malformed`.

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

**Credentialed calls** [decided, S21–S24]: a call whose authority is a
credential proof (`proving.md` §8), with no session and no signature.
Ingress verifies the proof and logs only the origin it proves.
- **The request:** `Credentialed`, a request kind of the node's binary
  API (`vos_wire` frames over a unix socket or QUIC with mutual TLS)
  addressed to an agent [decided, S41]. Its kind is read before its body,
  so the node sizes the frame before decoding it: at most 1.5 MiB plus
  `cap::REQUEST` plus the 4 KiB envelope. A gateway serves it over HTTP as
  `POST /agents/{agent}/credentialed`, `413` past the size; the gateway
  translates and holds no authority, and every check below is the node's.
  The body, in SCALE:

  ```rust
  pub struct Credentialed {
      pub instance: InstanceId,
      pub method: MethodId,
      pub arguments: Vec<u8>,          // at most cap::REQUEST
      pub nonce: [u8; 16],             // the client's, at random
      pub expires_ms: u64,             // by the node's clock
      pub format: u32,                 // 44 (S29); 43 for a device proof
      pub public: CredentialPublic,
      pub proof: Vec<u8>,
  }
  pub enum CredentialPublic {
      #[codec(index = 0)]
      Auth { map_root: [u8; 32], scope: [u8; 32], nullifier: [u8; 32], binding: [u8; 32] },
      #[codec(index = 1)]
      Owner { owner: [u8; 32], binding: [u8; 32] },
  }
  ```
  The enum's index is the statement's `kind`.
- **The node's clock:** the API's `Time` request answers the node's time
  in milliseconds, a SCALE `u64` (a gateway's `GET /time`). A client reads
  it before it picks `expires_ms`, because the proof binds that value and
  a refused expiry costs a new proof. The answer is not signed: a relay
  that lies about it makes the client pick an expiry the node refuses,
  which costs a new proof and nothing more, since ingress checks the
  expiry against its own clock. The node's key, which clients pin, keeps
  its own request (a gateway's `GET /`).
- **The binding digest:**
  `b = BLAKE2b-256("vos/cred/binding/v1" ‖ space ‖ agent ‖ instance ‖ method ‖ program ‖ kind ‖ arguments ‖ nonce ‖ expires_ms)`:
  `space` the `SpaceId`'s 32 bytes; `agent`, `instance` and `method` 4
  little-endian bytes each; `program` the statement's program id as 32
  bytes (the circuit's, or for a device proof the kernel's); `kind` one
  byte; `arguments` as the codec writes them (a `u32` little-endian
  length, then the bytes); `nonce`
  16 bytes; `expires_ms` 8 little-endian bytes. The proof's public
  `binding` is `C(T(binding), W(b))` (`proving.md` §8). So a proof
  authorizes one call: one space, agent, instance and method, one
  statement, one set of arguments, once, before `expires_ms`.
- **The guards,** from the handler's attribute into its
  `MethodSchema::credential`:
  - `#[msg(credential = Auth("login"))]` is
    `CredentialGuard::Auth { name, device: None }`. It admits `Anonymous`
    origins; `name`, 1–64 bytes, is the scope's. Its `device` field names
    the attestable kernel whose device proofs (format 43) it also takes,
    from M5 (`#[msg(credential = Auth("login"), device = "auth")]`); the
    field exists from the start, so M5 moves no pinned blob.
  - `#[msg(credential = Owner)]` is `CredentialGuard::Owner`. It admits
    `Owner` origins; the handler compares the digest with the owner of the
    row it debits (`ctx.owner()`), at apply, on the live row.
  - Only a `&mut self` handler takes one, and no role or `linearizable`
    beside it. A method without a credential guard refuses `Anonymous` and
    `Owner` callers (`Failure::Forbidden`).
  - An `Auth` guard needs its agent's credential actor (§6): installing a
    program with one into an agent without that actor fails
    `Failure::Credentials` (15).
  - **`once`** [decided, S43]: `#[msg(credential = Auth("vote"), once)]`
    admits each nullifier once in its scope. The nullifier is a stable
    pseudonym, so the guard, not the handler, keeps the set: apply records
    the system row `once(scope ‖ nullifier) → t`, `t` the batch time of
    its admission, kept for good; the scope digest names the space, agent,
    instance and guard name, so the rows are scoped by construction. The
    row is written only when the handler returns `Ok`, in the apply that
    ran it [decided, S47]: a refused ballot is not a cast vote, so a call
    the handler fails or refuses leaves the member free to try again,
    with a new proof (its `b` stays recorded). A repeat of an admitted
    nullifier is refused (`CredentialRefusal::Once` at ingress,
    `Refusal::Once` at apply). A new round takes a new name, so a new
    scope. `once` needs an `Auth` guard
    and is part of `CredentialGuard::Auth`, so it moves no pinned blob.
- **Ingress's checks, in order,** each cheap one before any dearer, every
  state read on this replica's applied state; each refusal is
  `Rejected(Credential(code))` (index 9 of `Rejection`), `code` a
  `CredentialRefusal` of the index shown, the codes in check order. Apply
  refuses under refine's `Refusal`, another enum; where both have a name
  (`Replayed`, `Once`), the text says which:

  | # | check | refusal | a gateway's HTTP |
  |---|---|---|---|
  | 1 | the frame within its kind's size | the frame error `Oversize` (not a credential code) | 413 |
  | 2 | it decodes, exactly | `Malformed` (not a credential code) | 400 |
  | 3 | this node serves the agent | `NoAgent`, `Elsewhere`, as for calls | 404, 421 |
  | 4 | the node's space has a genesis (its `SpaceId` is not `NONE`) | `NoSpace`, 0 | 403 |
  | 5 | `format` is a credential or device format this node admits | `Format`, 1 | 403 |
  | 6 | `proof` within its format's cap (44: 512 KiB; 43: 1.5 MiB), `arguments` within `cap::REQUEST` | `Size`, 2 | 403 |
  | 7 | `now ≤ expires_ms ≤ now + 120 s`, `now` the node's clock | `Expiry { now }`, 3 | 403 |
  | 8 | the instance's method exists and has a credential guard | `Method`, 4 | 403 |
  | 9 | `public`'s kind is the guard's, and the format proves it for this method (43: auth, for a guard that names a device kernel) | `Kind`, 5 | 403 |
  | 10 | auth: `scope` is the one the guard's name gives | `Scope`, 6 | 403 |
  | 11 | `binding` is `C(T(binding), W(b))` of this request | `Binding`, 7 | 403 |
  | 12 | `b` is not recorded | `Replayed`, 8 | 409 |
  | 13 | auth with `once`: `(scope, nullifier)` not recorded | `Once`, 9 | 409 |
  | 14 | auth: `map_root` is in the credential actor's ring | `RootUnknown`, 10 (`RootRefusal::Unknown`): retryable, fetch the path again, or ask another replica; an honest member meets it on a replica's lag, a root replaced at its own batch time, or one past the ring's 64 entries (§6) | 503 |
  | 15 | auth: `map_root` is the ring's newest, or was superseded at most `ROOT_MAX_AGE` before the replica's latest applied batch time | `RootStale`, 11 | 403 |
  | 16 | a verification slot is free: fewer verifications in flight than the node's budget (by default twice its executor threads) | `Busy` (not a credential code) | 503 |
  | 17 | on an executor, the proof decodes; its interaction PoW and its PoW hold, checked before any Merkle decommitment is read; then it verifies under the program for its kind | `Proof`, 12 | 403 |

  Then the call goes to the agent's leader as `Input::Credentialed`,
  forwarded as a call is by a replica that does not lead, and its answer
  is `Ran { outcome, at }` once this replica has applied it, or apply's
  refusal under the same codes. `Proof` is one code for every failure, so
  a refusal says nothing of where a proof failed; a proof with a wrong PoW
  costs the node a few hashes. There is no bucket per scope or method for
  an attacker to drain: the bounds are the node's connections and its
  verification budget.
- **The log carries** `Input::Credentialed` (index 10 of the batch's
  `Input`: the session-less kind §15 step 0 reserves), never the proof,
  the nonce or the format, so `cap::REQUEST` and a log entry's size are
  unchanged:

  ```rust
  pub struct CredentialedInput {
      pub origin: Principal,           // Anonymous { scope, nullifier }, or Owner(digest)
      pub instance: InstanceId,
      pub method: MethodId,
      pub arguments: Vec<u8>,
      pub binding: [u8; 32],           // b
      pub expires_ms: u64,
      pub root: Option<[u8; 32]>,      // auth's map_root
  }
  ```
- **At apply** (refine, in the batch's order, at the batch's time `t`):
  1. `expires_ms < t`: refused, `Refusal::CredentialExpired` (7);
  2. `b` recorded: refused, `Refusal::Replayed` (8);
  3. auth: `root` neither the ring's newest nor superseded at most
     `ROOT_MAX_AGE` before `t`: refused, `Refusal::StaleRoot` (9);
  4. a `once` guard: `once(scope ‖ nullifier)` recorded: refused,
     `Refusal::Once` (10);
  5. `b` recorded, the system row `binding(b) → expires_ms`, collected by
     the sweep at `expires_ms` plus 60 s through the due index;
  6. the method runs, its caller the origin, under its guard; whatever it
     returns, `b` stays recorded (`Failure::Forbidden` or a trap consumes
     the input);
  7. a `once` guard: the row `once(scope ‖ nullifier) → t` recorded only
     if the method returned `Ok`, in this apply, beside its writes
     [decided, S47].

  A refused input writes nothing. So a proof replayed at another replica
  runs once, and a revocation binds every replica at the same batch. A
  duplicate is answered `Refusal::Replayed` at apply (or
  `CredentialRefusal::Replayed` at an ingress that has applied the
  first), without the first call's outcome [decided, S39]: a client that
  lost its answer reads state (a balance, a record).
- **On JAM,** an agent whose builder is one of the space's nodes takes a
  credentialed input as it takes any: its builder's ingress verified the
  proof, under the trust-boundary rule above.
- **Device proofs** (format 43, M5) authorize exactly what an auth proof
  does [decided, S24] and take the same checks (`proving.md` §8).

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
    non-members (§14).
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
  replicas, roles, reports) [decided, S46]: requests of the node's binary
  API, each signed by an operator key the node's config lists, with a
  nonce and an expiry as a call's; the node records the nonce until the
  expiry and refuses an unlisted key, a replay or an expired request. A
  gateway, and s4's operator console in it, only relays them: the
  console's operator signs in their own client, so a relay keeps nothing
  it can reuse. Until signed operator requests are built, the node
  accepts operator kinds on its local unix socket only, its file mode
  the access, and refuses them over QUIC (`slice-7-mobile.md`, 7.10b).
- **Registration of identities** is the space's choice: open
  self-registration, invitation (the onboarding tokens master had), or
  a governance decision.

**The credential actor** [decided, S21 and S25; its tree is `proving.md`
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
  one [decided, S25]. It is public: the app shows it and pins it at a
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
  - its struct: `handle`, `next` (the lowest slot never used) and `count`
    (the members enrolled).
- **The ring:** a write whose batch time equals the newest entry's
  `since` replaces that entry's root; any other appends an entry, dropping
  the oldest past 64; the install writes the empty tree's root. A root is
  **accepted** while it is the newest, and for `ROOT_MAX_AGE`
  (10 minutes, `vos_wire::defaults`; not the venues' `MaxRootAge`) after
  the next entry's `since`, the
  moment it was superseded. Ingress measures that by the replica's latest
  applied batch time, apply by the batch's (§5). So a revocation binds
  within `ROOT_MAX_AGE` of its batch, and an honest member's path stays
  good for as long after any change to the tree. The 64 entries bound
  storage, and in a busy space freshness too: a root that has fallen out
  is `RootUnknown`, so 64 tree-changing batches within `ROOT_MAX_AGE` make
  an honest root unknown before it is stale. `RootUnknown` is retryable by
  a path refetch, and the device library refreshes its path well within
  64 batches' time (`slice-7-mobile.md` pin L).
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
    enroll another (the demo's ledger rows take the same two steps,
    `invite_row` and `claim_row`, `slice-7-mobile.md` 7.11). A member with
    no client key of its own has its claim sent by the app that serves it
    (the demo's gateway app, under its own client key): an ordinary
    client's authority, bounded by the invitation, which names the
    digest;
  - `revoke(member)`, role `registrar`: the leaf back to the empty leaf,
    the slot freed; for a member only invited, the invitation withdrawn;
  - queries, any caller: `path(member) → Option<(root, slot, siblings)>`,
    the 32 siblings from the leaf's level up; `root() → (root, since)`;
    `handle() → [u8; 32]`; `count()`, the members enrolled. A query is
    signed by a client key like any other; the device library signs each
    with a key drawn for it alone.
- **Its cost:** 33 calls of `0x402` an enrollment (32 a revocation, whose
  leaf is the empty one; an `enroll_many` shares the nodes its members
  have in common), each 2,400 gas to the actor. The VOS host serves it
  natively and a JAM-deployed agent through the shim's software
  permutation (about 37,600 gas), so the tree is a function of its writes
  on both [measured, `slice-7-progress.md` 7.9].
- **Re-founding** (`slice-7-mobile.md`, pin D′): the runbook installs the
  new space's credential actor with the ended space's handle and re-seeds
  it with `enroll_many` from the ended space's `member` digests, with no
  member action. Slots may move, and a member fetches its path again.

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
  becomes the global handle the owner refuses. A method that admits a
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

**In a space first** [decided, S21–S25]: the first credentials are proven
to their own space's ingress, not across spaces. Membership (auth) proves
a leaf of the space's credential actor (§6) and yields an `Anonymous`
origin; ownership (owner) proves the secret behind a row's owner digest
and yields an `Owner` origin (§5). Their circuits, words and format are
`proving.md` §8's. Across spaces the pitfalls above hold as written; in a
space three of them take a simpler form:
- **No epoch in the leaf** (`member = C(T(member), s)`): revocation removes
  the leaf, and the device could neither keep an epoch nor the actor check
  one.
- **Freshness is time, not windows:** a root is accepted for
  `ROOT_MAX_AGE` after it was superseded (§6).
- **The scope carries the space:**
  `scope = C(T(scope), W(BLAKE2b-256("vos/cred/scope/v1" ‖ space ‖ agent ‖ instance ‖ name)))`,
  so no two agents' guards of one name, in one space or two, share a
  pseudonym, even for a member whose secret two spaces share.

**The in-space credential's threat model:**
- **Whom it protects against:** outsiders and the space's other members,
  not its operators. The log carries the origin ingress derived, never the
  proof (§5), so an operator can log an `Anonymous` or `Owner` origin it
  never verified, as it could run any call; members trust their space's
  nodes for integrity, as every cell of §3 does. A space that wants
  evidence turns on the non-repudiation side store, which keeps the
  proofs.
- **The device secret's containment, as it is** (its sources are
  `proving.md` §8's [decided, S42]):
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
    `rekey` moves its rows.
  - Each use takes the user's consent at the source (a biometric or the
    PIN at the Keystore; the PIN and a touch at a security key), so
    malware cannot evaluate it silently; one use is enough to keep `s`.
  - What `s` gives a thief: auth as its member in every scope of the space
    (and of every space sharing its handle), payment from every row
    `owner(s)` owns, and every nullifier the member has used or will use,
    so the member's past pseudonyms link to it. Revoking the leaf stops
    auth within `ROOT_MAX_AGE`; it does not stop payment, which reads no
    tree: the ledger's `rekey(row, owner)` and `freeze(row)`, under an
    operator role, do [decided, S37].
  - **The in-space ledger is custodial by design:** an operator who can
    `rekey` can move any row to a key of its choosing. It is the tier
    such a space picks [decided, S37]; the log attributes each `rekey` to
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
- **Revocation** binds every replica within `ROOT_MAX_AGE` of the
  revoking batch, by batch time (§5's apply rule): a revoked member's
  proof against an older root is refused then, whatever a lagging
  replica's ingress accepted. Within the window a revoked member can still
  authenticate.
- **What operators learn:**
  - from `path(member)`: which member digest is online, and from which
    address. The query's key is drawn for it alone and links nothing, and
    the library refreshes its path apart from its proofs (when `root()`
    moves and on a timer, never just before a proof, on a connection of
    its own) [decided, S38], so a fetch's time says nothing of a proof's.
    The leak is reduced, not closed: a proof from the same address still
    links its nullifier to the digest, and the digest to whoever the
    registrar enrolled. So `Anonymous` hides the member from the log's
    readers, other agents and other members, not from the operators of
    the nodes and gateways that serve its requests; that is full
    privacy's (§3, §8);
  - from the log: each auth call's scope and nullifier (a pseudonym's
    activity in one scope), each payment's owner digest (a public payer,
    S22), each credentialed call's arguments in clear (a payment's payee
    and amount beside its payer), and the metadata every cell leaks (§3);
  - from a tree change: every online member's library refreshes its path
    when `root()` moves, so each enrollment or revocation shows which
    member digests are online then (the timer's jitter spreads the
    fetches, it does not hide them); syncing the tree is the later fix;
  - from the tree: how many members there are and when each was enrolled
    or revoked; a leaf hides its digest, so whether a digest is enrolled
    is learned only by asking `path` for it;
  - from a copied handle: two spaces sharing a handle can link their
    common members' `member` and `owner` digests (their nullifiers stay
    apart).
- **Denial of service:** every check but the proof's costs microseconds
  and is checked first; the PoW precedes every decommitment; a budget
  bounds the verifications in flight; the request's decode and the
  verifiers are fuzzed.

**Opt-in linking:** a holder can prove "the same person as identity X in
space A", and only to whom they choose.

## 8. Full privacy: personal spaces and a shielded pool (postponed)

**Postponed** [decided]. These are the primitives that serve the "hidden
from the operators, actor anonymous" cell, recorded so that the
primitives built first don't preclude them. A space opts in: each space
chooses its privacy tier [decided, S37]. Fully private, cash-like
payments are this section's: membership proven privately, a hidden
payer, the shielded pool. Slice 7 measures only that a proof of
membership and payment together fits the phone's budget (`proving.md`
§8).

- **A personal space** is the VOS runtime inside the person's wallet
  app: a space with one node, whose state lives on the device.
  - It holds notes, keys and credentials, and the master secret its
    pseudonyms and keys derive from.
  - **Durability is its threat, not operators.** Recovery is required:
    a seed, a guardian threshold, or a passkey-wrapped secret, with
    passkeys as the default experience.
  - A hosted replica stores encrypted snapshots and holds no keys;
    otherwise it is custody.
- **The shielded pool needs integrity without trusting its host,** not
  only secrecy. Its users are exactly those who do not want to trust
  operators. So it runs as a JAM agent (slice 4's JAM mode), or in a
  space that proves its transitions, and it verifies each spend's proof
  in its guest.
- **One pool shared by many spaces,** not one per space. The anonymity
  set is everyone who uses it.
- **Its costs on JAM:**
  - a final proof costs about 80M gas of refine (the JAM statements
    service's, measured), so about 60 fit a work package's 5e9;
  - scanning notes held on JAM needs the JAM light client in the
    personal space.
- **An anonymous input** travels the client path without a session:
  - self-authenticating, deduplicated by its nullifier;
  - no acknowledgement;
  - carrying a fee note inside its proof.
- **Note discovery** (§14):
  - scanning by the personal space, with a one-byte view tag per note;
  - the sender's direct delivery through the end-to-end encrypted
    messenger as the fast path;
  - detection keys deferred.
  - With every key derived from one master secret, a rescan of the
    pool doubles as recovery.
- **The relay layer:**
  - an existing anonymity network (Tor, Arti bundled in the node, or
    Nym) in front of the pool's ingress, not a network of our own;
  - this design fixes only the input format: no session, a few padded
    sizes, accepted from any relay.
- **Proving on the device:** a fixed spend circuit in the Stwo and
  Poseidon2-M31 family, with masking. Its statement is defined to be
  the wallet kernel's, so the general zkPVM can take over once it is
  masked and fits a phone.

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
  - **the light client** (header finality tracking) is a slice of its
    own.
- **Guards are the same on both sides:**
  - a VOS actor can require an input from a given JAM service;
  - a JAM agent can require one from a registered space's
    representative, carrying a valid proof.
- Crossing the boundary is a message, never a synchronous call. JAM's
  hops take blocks.

## 11. Anchors: the root chain, per space

- **The ordered root sequence already exists:** JAM mode's root chain,
  in which each package's accumulate swaps one root for the next, in
  order (slice 4). A space cannot prove two transitions from one root
  to two parties.
- **Missing is a root for the space,** not just for each agent:
  - a space has many agents, each with its committed root;
  - its representative agent keeps a space-level root over its agents'
    roots, per window: a committed map keyed `(agent, kind, w)`, the
    value an agent's root at its cut of w, itself cut at `B_w + D` (the
    window's boundary plus a close delay of `min(L/5, 2 min)`); the space
    root is `S_w = BLAKE2b-256("vos/space/v1" ‖ space ‖ w ‖ A_rep)`, over
    the representative's agent root at that cut (`slice-6-on-chain.md`,
    on spaces, windows, roots and anchors).
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
    JAM. The anchor's signer is checked against the space's anchor keys
    listed at the venue, which its controller adds and removes (a
    removed key's anchors are refused, and an anchor refused for its key
    is signed again with a listed one). The anchor gives outsiders
    ordering;
  - two anchors of one window under different roots are an
    equivocation: the venue suspends the space until the controller has
    delisted both keys;
  - **a space moves venues** by a migration its controller signs at the
    old venue: windows from the migration's on anchor at the new one
    only, and the old venue keeps judging statements rooted before it.
  - integrity comes only from a proof that names the anchor.
- **A venue anchors only a window its own clock has closed;** every
  deadline between parties is the venue's time.
- **Cost:**
  - on Kreivo an anchor is a ~170-byte extrinsic, a statement about 4 ms
    of ref_time unmasked [measured] and about 0.43 UNITS of length fee,
    plus a refundable deposit, all paid by the space's sovereign account;
    on JAM a statement is about 80M gas of refine;
  - "this root is in the sequence" is a witnessed read in the
    representative agent's state, which slice 4 made cheap: on JAM,
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
  in accumulate; on Kreivo, the controller (an `AccountId`) rotates the
  authorities and anchor keys.
- **Exit and disputes** need rules, not yet designed. A space's name on
  exit is released only after its deposit's delay, so exit cannot be
  used to squat.
- **Policy stays mechanical:** fees, names, accepted versions, disputes.
  It never reaches into a space's internals.

## 13. cipher-clerk

A design and implementation review (2026-10-15) found:
- **The plain double-entry kernel** is careful, with about 320 tests
  worth keeping as its specification.
- **One critical gap in the kernel:** an entry's currency is never
  checked against its account's, so a debtor converts currencies at
  1:1 on their own signature. Master's `clerk-ledger` inherits it and
  is being fixed.
- **The privacy stack proves nothing yet:**
  - every shipped verification is the issuer's signature;
  - the disclosure and settlement statements read no state;
  - the voucher statement names no recipient and sequences no roots;
  - the spend check lacks owner binding and unique nullifiers, so a
    sender can spend a note back.

**The fix,** in cipher-clerk's `docs/viability-plan.md` (branch
`viability`, local):
1. the soundness fixes;
2. then the shape a VOS agent needs:
   - plain integer amounts;
   - authority from ingress instead of signatures in the kernel;
   - explicit encodings;
   - no roots of its own;
   - settlement as a pure function whose output names both spaces, the
     window and a sequence;
3. the note model redesigned on paper and reviewed before any private
   tier code. That last phase follows §8 and is postponed with it.

## 14. Decisions and what remains open

**Taken** [decided], subject to the reviewer's check:
- **The trust-boundary rule, per executor (§5):**
  - a space verifies at ingress;
  - a public JAM agent takes only chain-authenticated origins and
    proofs;
  - non-repudiation is an ingress option, off by default.
- **The identity replica's contract (§6):** bootstrap, two-sided lag,
  schema-declared linearizable epochs, monotone epochs.
- **The origin ABI and input kinds reserved in step 0 (§15).**
- **One attestation primitive** (§5).
- **Two axes and primitives per cell;** spaces choose (§3).
- **The identity agent replicated on every node** (§6).
- **Epochs plus short expiries** (§5).
- **First credentials:** membership, then solvency (§7).
- **Postponed:** full privacy, personal spaces, the shared pool, the
  relay layer and the holder-side prover for personal spaces (§8); the
  credential AIR and the device profile are slice 7's (`proving.md` §8).
- **Registry:** a charter with handover triggers, a delay on version
  changes, pseudonymous registration (§12).
- **Who pays:**
  - a member acting in a space: the space, with rate limits per
    identity;
  - a JAM service's message: the sender pays JAM, and the receiver
    pays for its light client;
  - anonymous non-payments: rate-limiting nullifiers, one action per
    period per scope;
  - anonymous payments: a fee inside the proof;
  - registered spaces: a deposit plus fees.

**Open,** each deferred by the owner to a named point:
1. **The identity replica's shape:** a non-voting role added to
   vos-raft, or the applied state shipped to non-members as a
   read-only follower (§6). Decided when the first build is planned.
2. **The handover triggers' numbers** for the registry's governance.
   Decided with the registry slice.
3. **Where the shared pool first runs:** a JAM agent, or a proving
   space run by the root space. Decided when full privacy is
   unpostponed.

## 15. Proposed staging

0. **Into the core model** (§5, §6.5):
   - the attestation primitive;
   - the trust-boundary rule, as quoted in §5;
   - the origin ABI with its kinds and their codec indexes (§5):
     `Client`, `Agent` and `Instance` built; `Anonymous` and `Owner`
     with the credential verifier; `Identity` and `Jam` reserved;
   - the input kinds: `Request` in a session, and the session-less
     `Credentialed` (§5), which anonymous inputs of the shared pool (§8)
     will also take;
   - rate limiting keyed by origin kind.
1. **Second opinions on each draft** (Fable): draft 4's are folded
   here.
2. **First build** (the operator-readable row, independent of proving):
   - the identity agent replicated on every node;
   - authenticators and signature verification at ingress (ed25519,
     P-256);
   - origins and guards;
   - grants with epochs;
   - device-signed sessions.
3. **With slice 5's prover and Clerk:**
   - masking first;
   - space-level anchors;
   - Clerk's first tier on cipher-clerk's `viability` branch, with its
     window-settlement attestable;
   - credentials (membership, solvency);
   - anonymous origins with scoped nullifiers on the client path.
4. **The registry and the root space,** with the JAM light client.
5. **Postponed, opt-in per space:** personal spaces, the shared pool,
   the holder-side prover for personal spaces, the relay layer and note
   discovery, with
   cipher-clerk's note redesign as their first application.
