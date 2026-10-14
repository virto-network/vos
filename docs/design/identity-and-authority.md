# Identity and authority

Draft 3 of a design run on who acts in a space, how a request proves
it, what each actor may do, and what anyone outside a space learns.
- Draft 2 adopted the owner's idea of personal spaces.
- Draft 3 folds a second opinion (Fable):
  - secrecy and anonymity as two axes;
  - one primitive for grants and credentials;
  - ingress verifying, so guests never check signatures;
  - personal spaces as device-local runtimes;
  - the transport an anonymous sender needs.

Nothing here is decided: the owner weighs it over several rounds before
any slice is planned on it. Tags as in the core model.

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
- **Privacy where it is needed.** Most spaces trust their operators.
  Some actions must be hidden even from them, as cipher-clerk's fully
  private payments, proven on the user's device, intend.
- **One trust model** (the owner's idea): a space's operators see
  everything in it. Privacy from operators comes from keeping secrets in
  a space of one's own, a personal space, and sending a shared space
  only proofs.
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
- Origins, as Substrate has them, are worth a look but not a given.

## 2. What exists today

- **A caller is a principal:** a client's key or another agent.
- **Each agent keeps a table** from principals to role bytes, set by the
  operator's CLI, and a handler names the role it needs. A workflow's
  role is checked at its start.
- **Clients sign each request** with their key, inside a session the
  client names (slice 3).
- **Ingress authenticates clients into principals,** and the agent
  receives the authenticated origin. Guests never check signatures
  (core model §5).
- **Nodes** have keys of their own, and a space's nodes trust each other:
  the trust model is crash faults only.
- **No identities, devices, delegation or anonymous callers.**

## 3. Two axes: who can read the data, and who is known to act

Secrecy and anonymity are different things, so they are two axes, not
one tier:

| | **Actor named** | **Actor anonymous** |
|---|---|---|
| **Data the operators can read** | plain actor state, signed origins: most spaces | proof origins with a nullifier: anonymous votes, polls, rate-limited posting |
| **Data hidden from the operators** | data encrypted to its members, as the messenger's end-to-end encryption does, or held in a personal space | a personal space plus a shared shielded pool: private payments |

- **Every cell keeps one trust model:** a space's operators see what is
  in it. What they cannot read was never given to them in clear: it
  was encrypted to its members, or kept in a personal space.
- **Facts proven about oneself** (credentials, §7) sit in the anonymous
  column with no secret state at all: the prover shows a fact and stays
  unlinkable.
- **Across spaces,** every cell discloses only what a proof returns.
- **A personal space** (§8) is a topology that serves the "hidden from
  the operators" row, not a tier of its own.

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

**Ingress verifies; the log carries the result; guards read state.**
This keeps the decided principle that guests never check signatures:
- verifying ed25519 or P-256 signatures in refine would be paid on every
  replica;
- on JAM it would be paid in software, with no signature precompile and
  BLAKE2b alone at about 20k gas a compression.
- **At ingress** (the node), a request's evidence is checked: its
  device's signature, the attestations it presents, a proof. It is
  reduced to an origin plus an authority set: the claims it was shown
  to hold, narrowed.
- **The log entry carries** that origin and authority set, never the
  evidence.
- **A guard on a method** reads only the logged origin, the authority set
  and state (roles, grants, epochs). So every replica, and a JAM
  witness, evaluates the same bytes.

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
wants one says "from agent G, with claim `decision(d)`". Substrate's
collective origins become a shorthand for that guard.

**Attestations, used two ways:**
- **Grants,** shown in clear inside a space. An identity delegates a
  narrowed grant to a device or an app, for example: "this app may call
  `transfer` on actor A, up to 100, until Friday".
- **Roles** are named claim sets an issuer grants. `#[msg(role = ..)]`
  stays, as one kind of guard.
- **Credentials,** proven in zero knowledge against the issuer's anchored
  root (§7).

**Object capabilities are the special case** where a grant names one
instance and one method, so this design subsumes them; it need not argue
against them.

**Revocation by epochs:**
- each identity, and each device under it, has a revocation epoch in
  the identity agent;
- a grant carries its issuer's epoch at issue;
- bumping the epoch voids every earlier grant, at the cost of one state
  read at ingress;
- short expiries, in batch time (monotone, core model §8.4), cover the
  rest;
- a list is for selective revocation only;
- credentials are revoked by freshness (§7).

**On VOS and JAM: the same guards, different evidence.**
- Inside a space the evidence is signatures and grants, checked at
  ingress.
- Across the boundary the origin is the sending service or space, and the
  authority is a proof (§10).

## 6. Identity in a space

- **The identity agent:** a system agent per space.
  - **An identity's id** is the hash of its creation record, as agent ids
    are, never a key.
  - **It holds** a set of authenticators with a policy (any one device, a
    threshold, one device within limits), a revocation epoch, and
    recovery.
- **Authenticators:**
  - ed25519 keys, as today;
  - SSH keys, signing through an agent without exposing the key;
  - passkeys (WebAuthn, P-256);
  - hardware tokens.
  - Ingress verifies them all, so this needs signature checks at
    ingress, not precompiles inside guests.
- **Ingress needs the identity agent's table:**
  - a device must resolve to its identity and epoch before the request
    is logged;
  - but roles live per agent, and ingress has no read across agents.
  - **Two shapes:**
    - the identity table is a read-only view every node keeps synced (a
      Merge scope fits);
    - or ingress asks the identity agent, a round trip per request.
  - This decides how a session opens, so it comes early (§14).
- **Operators are identities too:** a node's key is bound to its
  operator's identity, so hosting and acting are two grants, never one
  key for both.
- **Registration of identities** is the space's choice: open
  self-registration, invitation (the onboarding tokens master had),
  or a governance decision.

## 7. Credentials: facts proven about oneself

**What it is:**
- An actor in one space attests a fact about one of its identities,
  such as "reputation at least 50", "a member since 2025" or "a verified
  human". The attestation is a leaf under the issuer's committed root.
- The holder proves the fact to another space, or to JAM, in zero
  knowledge against the issuer's anchored root (§11), without revealing
  the identity or anything beyond the fact.
- This is the portable standing the owner described, with no global
  handle.
- A Kreivo pass becomes a credential proven against Kreivo's state, not
  an authenticator of its own.

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

## 8. Personal spaces

**What it is** (the owner's idea):
- A personal space is the VOS runtime inside the person's wallet app: a
  space with one node, a Raft group of one (the node already runs
  groups of one replica), whose state lives on the device.
- It holds the person's secrets: notes, spend and viewing keys,
  credentials, and the master secret their pseudonyms derive from.
- It is a full space with one node, not a lighter kind. A note set and
  its spent marks need linearizable updates across one person's
  devices, or the person double-spends against themselves.

**Durability is the threat, not the operators.**
- A lost phone is lost notes, keys and credentials. A Raft group across
  phones does not help, because phones are offline and a quorum is
  rare.
- **The shape is one primary device plus encrypted snapshot replicas:**
  other devices, or a hosted store.
- **A hosted personal space is an encrypted replica that holds no keys,**
  not an operator; otherwise it is custody under a nicer name.
- **Recovery** (guardians, a delay, a seed) is the base case here, not
  an option.
- **Pseudonyms derive deterministically** from the master secret and the
  space's id, so a seed recovers every one of them.

**Private payments: a message between spaces, but not on the pair
transport.**
- **The shared space holds the shielded pool:** note commitments, spent
  nullifiers, anchors, and the notes waiting for their recipients.
- **The payer's wallet actor proves, on the device:** "I own these notes
  under anchor A; these are their nullifiers; these new commitments
  balance them".
- **An anonymous message cannot use the agent-pair transport,** because
  pairs, acknowledgements and `Behind` all name the sender agent and get
  exactly-once by its sequence. So the proof travels the client path
  without a session:
  - a self-authenticating input, deduplicated by its nullifier (the
    proof is the idempotency key);
  - no acknowledgement and no reply: the sender learns of its success by
    watching the pool's public state, as a wallet watches a chain.
- **Anonymous inputs need a cost,** probably a fee note inside the proof,
  or spam is free.
- **The pool checks the proof at ingress,** applies the new commitments
  and the notes, and can net-settle with other spaces on JAM.

**Two dependencies that are the actual privacy work:**
- **A relay layer.** Which node and network address submitted an input,
  and when, links the payer as surely as a name would. It needs a track
  of its own, with an owner.
- **Note discovery.** Notes encrypted to a recipient's viewing key can be
  found in two ways, and one must be chosen and costed:
  - the recipient scans the whole pool, at a cost that grows with it
    (the light-client problem shielded chains have);
  - or detection keys flag candidate notes, as cipher-clerk's fuzzy
    message detection does, which is experimental today.
  - "Receiving needs no one online" depends on this choice.

**Proving on the device:**
- the spend kernel is small, around 0.2 to 0.5M steps with precompiles
  by S5's estimate;
- proving it on a phone needs the mobile prover work, or a fixed
  circuit (§14).

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
  which is the space's representative agent. Its authority is a proof.
- **From JAM to a space:**
  - a JAM agent's outbox is public state;
  - the space reads it through a JAM light client, with proofs of
    inclusion against JAM's state root, and the input enters with the
    origin `Jam { service }`.
  - **The light client** (header finality tracking) is a slice of its
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
  order (slice 4). It stops a space proving two transitions from one
  root to two parties, a gap cipher-clerk has today (§13).
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
    representative agent's state, which slice 4 makes cheap.
- **Statements disclose only their return value:**
  - "this window's net settlement with space B is X";
  - "this account's balance is at least Y";
  - "a member of set S, once in this scope".
- **Prerequisites,** on the prover and privacy track (core model §11.4):
  - zero-knowledge masking (the pinned Stwo has none);
  - hiding commitments for public outputs;
  - fixed proof shapes;
  - aggregation.

## 12. The root space and the registry of spaces

- **A registry agent on JAM,** public:
  - spaces register a name, their representative agent and their policy
    declaration;
  - it records fees or deposits, which also answer spam;
  - it holds what spaces must agree on: the transpiler versions and
    agent program hashes the verifiers accept, so upgrades are a
    registry decision.
- **Who governs it:**
  - at first the root space (Virto), as a DAO of its members, whose
    decisions reach the registry as messages from its governance agent;
  - later, a collective of registered spaces, each voting through its
    representative.
  - Moving governance is a decision, not a migration.
- **A space's own keys** (its builder's signing key, behind
  `package::identity(service)`) rotate by a governance decision applied
  in accumulate.
- **Who pays on JAM:**
  - a space's representative agent holds a balance;
  - a personal space has none, so the pool's space sponsors its
    cross-space payments.
- **Exit and disputes** need rules, not yet designed.
- **Policy stays mechanical:** fees, names, accepted versions, disputes.
  It never reaches into a space's internals.

## 13. cipher-clerk against this design

**What it has:**
- a double-entry ledger with Pedersen-committed amounts;
- vouchers between clerks;
- settlement claims;
- viewing keys;
- notes with nullifiers;
- experimental fuzzy message detection and stealth addresses;
- a state root over six depth-128 trees.

**Where its pieces land:**
- **Its first use case** is the named, operator-readable cell, with
  proofs across spaces. It fits as is, once its proofs bind what they
  claim.
- **Its private payments** are the personal space plus shielded pool
  cell (§8):
  - its notes and keys belong in the personal space;
  - its note pool belongs in the shared space;
  - its spend check becomes the wallet actor's kernel.
  - It has no prover yet, and its spend check is not yet a circuit.

**Before an actor is built on it, a design and implementation review
should settle:**
- **the spend statement's owner binding:** the check never ties the
  spending key to the note's owner;
- **what "owner" means:** it is used inconsistently across the CLI,
  examples and `open`;
- **nullifiers:**
  - a sender-chosen `rho` lets two notes share a nullifier;
  - with no key split, proving can't be delegated without spend
    authority;
- **one key** serving for signing, viewing, nullifiers and detection,
  with no rotation;
- **ordered roots:** a clerk can prove two transitions from one root,
  which §11's anchors answer;
- **the voucher statement:** it names neither the recipient nor the
  issuer;
- **proofs that bind nothing:** disclosure and settlement are not tied
  to state, and `disclosure::transfer_existed::check` is empty;
- **the single registrar key** and the operator's custody of pooled
  funds;
- the move to the compressed tree, and docs that have fallen behind.

This review belongs before slice 5 builds Clerk.

## 14. Questions for the owner

In the order their answers are needed:
1. **The ingress principle:** keep "guests never check signatures:
   ingress verifies, the log carries the origin and its authority"? This
   draft depends on it.
2. **One primitive:** grants and credentials as one attestation, shown
   in clear or proven?
3. **Secrecy and anonymity as two axes** (§3), each cell with its
   mechanism?
4. **Identity at ingress:** a synced read-only view of the identity
   table on every node, or a round trip to the identity agent per
   session?
5. **Revocation by epochs** plus short expiries, with lists only for
   selective revocation?
6. **Personal spaces:**
   - a full space with one node inside the wallet app;
   - recovery as a requirement;
   - a hosted replica that holds no keys.
   Agreed?
7. **The relay layer:** in this design's scope, or a dependency track
   with its own owner?
8. **Note discovery:** scanning, or detection keys?
9. **Who pays,** per origin kind, and the fee for anonymous inputs?
10. **The device prover:** a fixed spend circuit, or the general zkPVM
    fitted to phones?
11. **The root space:** Virto governing the registry first, and what
    triggers moving it to a collective?
12. **Credentials:** which facts first? They shape the first kernels.

## 15. Proposed staging

0. **Write the attestation primitive and the origin ABI** into the core
   model (§5, §6.5), with the ingress principle stated.
1. **This design,** over more rounds with the owner, with a second
   opinion on each draft.
2. **A review of cipher-clerk** against §13, before slice 5.
3. **First build:**
   - the identity agent, authenticators, origins and guards;
   - grants with epochs;
   - device-signed sessions;
   - the identity view at ingress.
   - It covers the operator-readable row, independent of proving.
4. **With slice 5's prover:** space-level anchors, credentials, scoped
   nullifiers, anonymous origins on the client path.
5. **Personal spaces and a shielded pool,** once a device prover, the
   relay layer and note discovery exist, with cipher-clerk's private
   payments as the first application.
6. **The registry and the root space,** with the JAM light client.

**Dependencies, by name:**
- the relay layer;
- the JAM light client;
- the device prover;
- signature verification at ingress (ed25519, P-256);
- the identity view at ingress;
- zero-knowledge masking and aggregation (the prover track).
