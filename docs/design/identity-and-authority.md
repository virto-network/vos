# Identity and authority

Draft 4 of a design run on who acts in a space, how a request proves
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

**Verification happens where the executor's trust boundary is**
[decided]:
- **Authority from a party the executor already trusts** is checked
  where the request enters. Such parties are a space's own members,
  through its nodes, and a JAM agent's own builder.
  - At ingress, a request's evidence (its device's signature, the
    attestations it presents) is reduced to an origin plus an authority
    set: the claims it was shown to hold, narrowed.
  - The log entry carries the origin and the authority set, never the
    evidence.
  - A guard reads only the logged origin, the authority set and state.
    So every replica, and a JAM witness, evaluates the same bytes.
  - Guests never verify signatures: on JAM there is no signature
    precompile, and a software verification would be paid by every
    replica.
- **A claim that strangers must be able to check** is a proof, and the
  agent that relies on it verifies it in its guest. Examples are a
  settlement claim between spaces, a spend into a shielded pool, and
  a credential.
- **No signatures in the log** means an operator cannot prove to an
  outsider what a member did: deniability for members. A space that
  needs non-repudiation, for disputes, keeps the request signatures
  in a side store under its own policy.

**Four kinds of origin:**
- `Identity { id }`: a person or service in this space, through a
  device;
- `Agent { id }`: another agent of this space;
- `Jam { service }`: a JAM service, authenticated by the chain or a
  light client;
- `Anonymous { scope, nullifier }`: a proof that the sender holds a
  claim, once in this scope.

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
- short expiries, in batch time (monotone, core model §8.4), cover the
  rest;
- a list is kept inside a space only to revoke one particular grant;
- credentials across spaces lapse by freshness (§7). No revocation list
  ever crosses a space boundary, so none leaks who was revoked.

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
    unreachable;
  - a method whose risk warrants it requires a linearizable read of the
    epoch.
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
- **Registration of identities** is the space's choice: open
  self-registration, invitation (the onboarding tokens master had), or
  a governance decision.

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
   holders;
2. **solvency:** "balance at least Y", from a Clerk ledger;
3. **reputation thresholds,** once a space keeps reputation.

**Pitfalls to design for:**
- **The issuer gives the holder the leaf's salt and path.** Salts derive
  from a version's seed the holder never sees (core model §9.3).
- **Timing links:** a credential issued in A and proven in B within one
  window links by time, so proofs should wait or batch.
- **A nullifier is scoped,** "once in this scope", and never global, or
  it becomes the global handle the owner refuses.
- **A leaf is keyed by the identity and its revocation epoch,** so an
  identity revoked in A cannot keep proving old facts in B.
- **Freshness:** a verifier demands a root within N windows, and the
  issuer drops a revoked leaf, so a credential lapses within N windows
  of its revocation.

**Opt-in linking:** a holder can prove "the same person as identity X in
space A", and only to whom they choose.

## 8. Full privacy: personal spaces and a shielded pool (postponed)

**Postponed** [decided]. These are the primitives that serve the "hidden
from the operators, actor anonymous" cell, recorded so that the
primitives built first don't preclude them. A space opts in.

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
    roots, per window.
- **Windows** run at a fixed cadence, minutes apart. A root that moved
  only on activity would leak activity.
- **Cost:**
  - an anchor is a work package per window per space, a few million gas;
  - a claim verified on chain also pays its verifier, about 10.7M cycles
    for the settlement verifier measured in slice 1;
  - "this root is in the sequence" is a witnessed read in the
    representative agent's state, which slice 4 made cheap.
- **Statements disclose only their return value:**
  - "this window's net settlement with space B is X";
  - "this account's balance is at least Y";
  - "a member of set S, once in this scope".
- **Zero-knowledge masking is required by the first tier, not only the
  private one.**
  - An unmasked STARK opens parts of its trace, so a settlement proof
    sent to JAM would leak the space's ledger to the world.
  - Masking (the pinned Stwo has none) therefore leads the prover
    track (core model §11.4), with hiding commitments for public
    outputs, fixed proof shapes and aggregation after it.

## 12. The root space and the registry of spaces

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
  in accumulate.
- **Exit and disputes** need rules, not yet designed.
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
- **The trust boundary rule:** ingress for trusted parties, proofs in
  the guest for claims strangers check (§5).
- **One attestation primitive** (§5).
- **Two axes and primitives per cell;** spaces choose (§3).
- **The identity agent replicated on every node** (§6).
- **Epochs plus short expiries** (§5).
- **First credentials:** membership, then solvency (§7).
- **Postponed:** full privacy, personal spaces, the shared pool, the
  relay layer and the device prover (§8).
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

**Open:**
1. **The ingress replica's consistency:** which methods warrant a
   linearizable epoch read, and is replication lag on revocation
   acceptable for the rest?
2. **Non-repudiation:** should the platform offer the side store of
   request signatures, or leave it to spaces?
3. **The handover triggers' numbers** for the registry's governance.
4. **Where the shared pool first runs,** once unpostponed: a JAM agent,
   or a proving space run by the root space.

## 15. Proposed staging

0. **Write the attestation primitive and the origin ABI** into the core
   model (§5, §6.5), with the trust boundary rule stated.
1. **A second opinion on this draft** (Fable).
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
   the device prover, the relay layer and note discovery, with
   cipher-clerk's note redesign as their first application.
