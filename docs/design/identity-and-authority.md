# Identity and authority

Draft 1 of a design run: who acts in a space, how a request proves it,
what each actor may do, and what anyone outside a space learns. Nothing
here is decided. Each section offers options and the one this draft
leans to, for the owner to weigh over several rounds before any slice is
planned on it. Tags as in the core model.

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
- **Privacy in tiers.** Most spaces trust their own operators. Some
  actions must be hidden even from them, as cipher-clerk's fully
  private payments, proven on the user's device, intend.
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
- **Each agent keeps a table** from principals to role bytes, set by
  the operator's CLI, and a handler names the role it needs
  (`#[msg(role = ..)]`). A workflow's role is checked at its start.
- **Clients sign each request** with their key, inside a session the
  client names (slice 3).
- **Nodes** have keys of their own, and a space's nodes trust each other
  (core model §5): the trust model is crash faults only.
- **No identities, no devices, no tiers, no delegation, no anonymous
  callers.**

## 3. Threat models: tiers of privacy

| Tier | Hidden from the public | Hidden from other spaces | Hidden from the space's operators | Example |
|---|---|---|---|---|
| **S, space-trusted** | everything but what a proof returns | everything but what a proof returns | nothing | most spaces; a community's channels |
| **X, private across spaces** | as S | as S | nothing | cipher-clerk's first tier: the ledger is plain to its space, and transfers between spaces settle on JAM through proofs |
| **O, blind to operators** | as S | as S | the member's data and which member acted; operators see commitments, nullifiers and proofs | cipher-clerk's later tier: private payments proven on the user's device |

**Tier O changes the core model's trust model** (§5) for the actors that
opt into it:
- **Execution:** their state is commitments, never plaintext, and their
  transitions are proven by the member, on a device, not executed by the
  space.
- **What the operators still do:** order and store the transitions, and
  check the proofs at ingress (§11.1 already verifies at ingress).
- **What they still learn:** timing and network metadata, unless a later
  layer hides it (mixing, relays). This draft names that layer and
  leaves it out of scope.
- **Every other actor** keeps today's model.

## 4. Concepts, kept apart

Most systems tangle these. Keeping them apart is what keeps the
primitives small.

| Concept | Answers | Lives in |
|---|---|---|
| **Identity** | who, stably, in this space | the space's identity agent |
| **Authenticator** | how a request proves it speaks for an identity | a device key, a passkey, an SSH key, a hardware token, a membership proof |
| **Membership** | what relation a principal has to the space: hosting, syncing, using | the space's roster |
| **Origin** | who a running call acts for, as the agent sees it | every request and message |
| **Authority** | what an origin may do here, and why | grants, roles, guards on methods |
| **Credential** | a fact one actor attests about an identity, that another may check | issued by actors, proven by their holder |
| **Pseudonym** | the identifier a space sees for a person | per space, unlinkable by default |

## 5. Authority: three candidate shapes

**A. Roles, extended.** Today's tables, with identities in place of keys
and a role for each tier.
- Simple, and what developers already know.
- No delegation, so a device or app holds a member's full power.
- Authority from a collective decision has no place in it.

**B. Origins and capabilities** [this draft's leaning].
- **Origins:** a call carries an origin, the authenticated subject:
  - an identity;
  - an agent;
  - a collective decision, which a governance actor produces when a vote
    passes;
  - an anonymous member, a proof with a nullifier for its scope.
  - This is Substrate's real insight: authority can be *derived*, not
    only held by a key.
- **Capabilities:** authority is granted as signed grants that can be
  narrowed and delegated, offline, without asking the space. For
  example: "identity X lets this app call `transfer` on actor A, up to
  100, until Friday". The grant chain rides with the request, and the
  agent checks it.
- **Roles become sugar:** a named bundle of capabilities granted to
  identities by the space.
- **Guards on methods:** a method states what it requires as a guard
  over the origin and its capabilities. `#[msg(role = ..)]` becomes one
  kind of guard, alongside others such as requiring a collective's
  decision or an anonymous member of a set.
- **The cost:** revocation. A delegated grant lives until it expires,
  unless the space keeps a revocation list that guards consult. Short
  expiries plus revocation by the grant's issuer is the usual answer.

**C. Object capabilities only.** No ambient identity in authorization at
all: whoever holds a reference to a method may call it, and identities
serve only accounting and audit.
- The cleanest model in theory.
- It fights the actor framework, where methods are named on an
  instance, and makes "who did this" a separate question.

| | A | B | C |
|---|---|---|---|
| Delegation to devices and apps | no | yes, narrowed | yes |
| Authority from collective decisions | no | yes (origins) | awkward |
| Anonymous callers | bolted on | an origin like any | natural |
| Revocation | the table | expiry plus a list | hard |
| Developer model | familiar | guards on methods | unfamiliar |
| Same on VOS and JAM | yes | yes | yes |

## 6. Identity in a space

- **An identity agent per space,** a system agent:
  - an identity has an id, a set of authenticators with a policy, and
    recovery;
  - **the policy:** any one device, a threshold of them, or one device
    within limits;
  - **recovery:** guardians, a delay, a registrar.
  - Requests are signed by a device; the node or agent resolves the
    device to its identity, and the origin is the identity.
  - **Sessions** (slice 3) are opened by a device and act for its
    identity.
- **Authenticators:**
  - ed25519 keys, as today;
  - SSH keys, signing through an agent without exposing the key;
  - passkeys (WebAuthn, P-256), which need P-256 verification: a
    precompile, as BLAKE2b has;
  - hardware tokens;
  - an anonymous membership proof, which proves "a member of this set"
    and nothing more.
- **Operators are identities too:** a node's key is bound to its
  operator's identity, so hosting and acting are one person in two
  roles, never one key for both.
- **The registrar of identities** is the space's choice: open
  self-registration, invitation (the onboarding tokens master had),
  or a governance decision.

## 7. Membership, as axes rather than a ladder

- **Hosting:** runs a node in the consensus of some agents. A space
  grants it per agent, and it is what placement already uses.
- **Syncing:** a light node or device that replicates only some agents,
  or some Merge scopes (§9.4), for reading and local use. It needs read
  authority per agent or scope, never write.
- **Using:** acts on actors through any node, with no node of its own.
- **Guests:** public methods only.

Hosting grants no application authority. An operator can stop serving
an agent, but approving a payment is a member's grant like any other.
Under tier S an operator can still read state, because it runs it;
tier O is where that changes.

## 8. Actors blind to their operators (tier O)

- **State:** an actor of this tier holds commitments (notes,
  balances), nullifiers and anchors, never plaintext. A member's device
  holds their private state and keys.
- **A transition** is a proof made on the device:
  - "these notes existed under this anchor";
  - "I own them";
  - "the new notes balance them";
  - "these nullifiers are theirs".
  - The space checks the proof at ingress, then orders and applies the
    public effects (new commitments, spent nullifiers) like any input.
- **Proving on a device** is the hard part:
  - our general zkPVM proves any PVM program, but needs gigabytes and
    seconds to minutes per segment (the mobile proving research);
  - fast payments on a phone probably want a small fixed circuit for the
    spend statement, proven by a light prover;
  - the general zkPVM stays for the space's own attestations.
  - Which prover is a decision of its own.
- **Composes with JAM:** the actor's anchors are what a space's JAM agent
  records, so a cross-space settlement can be proven against them.
- **Metadata** (timing, sizes, network addresses) still leaks to
  operators. Hiding it is a later layer.

## 9. Across spaces: pseudonyms and credentials

- **Pseudonyms:** a person has an identity in each space they join, and
  by default no space can link it to another.
- **Credentials:** an actor in one space attests a fact about one of its
  identities, such as "reputation at least 50", "a member since 2025"
  or "a verified human".
  - The holder carries the credential.
  - To another space, they prove the fact *about themselves*, with an
    attestable proof against the issuing space's anchored root, without
    revealing their identity there or anything beyond the fact.
- **Linking is opt-in:** a holder can prove "the same person as identity
  X in space A" when they choose to, and only to whom they choose.
- **This is the portable standing the owner described,** without a
  global handle that links a person everywhere.

## 10. The root space and the registry of spaces

- **A registry agent on JAM,** public:
  - spaces register a name, their representative agent and their
    policy declaration;
  - it records fees or deposits;
  - it holds what spaces must agree on, such as the transpiler versions
    whose kernel hashes the verifiers accept.
- **Who governs it:**
  - **at first,** the root space (Virto) governs it, as a DAO of its
    members, and its decisions reach the registry as collective origins;
  - **later,** governance can move to a collective of registered spaces,
    each voting through its representative agent (core model §12). The
    registry is designed so this move is a governance decision, not a
    migration.
- **Policy stays mechanical:** fees, names, dispute rules, accepted
  versions. It never reaches into a space's internals.
- **A space's own identity:** a space has keys of its own and a
  representative agent on JAM, through which it settles, votes and
  publishes anchors.

## 11. VOS and JAM: origins carried by their transport

**One rule:** a message's origin is the agent that sent it,
authenticated by whatever carried it.
- **Within a space:** the log and the placement, as today.
- **From a space to JAM:** the chain authenticates the sending service,
  which is the space's representative agent. Claims ride with proofs.
- **From JAM to a space:** a JAM agent's outbox is public state. The
  space reads it through a light client, with proofs of inclusion
  against JAM's state root, and the message enters the space with the
  origin `Jam { service }`.
- **Guards are the same on both sides:**
  - a VOS actor can require a message from a given JAM agent;
  - a JAM agent can require one from a registered space's
    representative, carrying a valid proof.
- Calls across the boundary are messages, never synchronous calls.
  JAM's hops take blocks.

## 12. Minimal disclosure: private state, public claim

- **Anchors:** a space's representative agent on JAM records an
  ordered sequence of the space's commitments, a root per window, each
  extending the last.
  - A proof's statement names the root it is about, and the verifier
    checks that root is in the sequence.
  - An ordered sequence is what stops a space proving two different
    transitions from one root to two different parties, a gap
  cipher-clerk has today (§13).
- **Statements disclose only their return value:**
  - "this window's net settlement with space B is X";
  - "this account's balance is at least Y";
  - "a member of set S, once in this scope" (a nullifier).
- **Nullifiers** are recorded where double use must be refused: in the
  space for its own scopes, on JAM for scopes that span spaces.
- **Prerequisites,** on the prover and privacy track (core model §11.4,
  slice 5):
  - zero-knowledge masking (the pinned Stwo has none);
  - hiding commitments for public outputs;
  - fixed proof shapes;
  - aggregation, so on-chain verification is affordable.

## 13. cipher-clerk against these tiers

**What it has:**
- a double-entry ledger with Pedersen-committed amounts;
- vouchers between clerks;
- settlement claims;
- viewing keys;
- notes with nullifiers;
- experimental fuzzy message detection and stealth addresses;
- a state root over six depth-128 trees.

**Its tier X** is its first use case, and it fits this design: the
ledger is plain to its space, and vouchers and settlements carry proofs.

**Its tier O** has the data structures (notes, nullifiers, a note pool)
but no prover, and its spend check is not yet a circuit.

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
- **ordered roots:** a clerk can prove two transitions from one root to
  two peers, which §12's anchors answer;
- **the voucher statement:** it names neither the recipient nor the
  issuer in what it proves;
- **proofs that bind nothing:** the disclosure and settlement proofs
  are not tied to state;
- **the single registrar key** and the operator's custody of pooled
  funds;
- the move to the compressed tree (slice 4's `vos-tree`), and docs
  that have fallen behind the code.

This review belongs before slice 5 builds Clerk.

## 14. Questions for the owner

1. **Authority's shape:** does B (origins and capabilities, roles as
   sugar) match your intent, or do you lean to A's simplicity for v1?
2. **Revocation:** short-lived grants with a revocation list held by the
   issuer, or a space-wide list every guard consults?
3. **Recovery:** which recovery should identities offer by default:
   guardians, a delay, or the registrar?
4. **Registration:** who registers identities in a new space by
   default: open, invited, or governed?
5. **Tier O's prover on devices:** a small fixed circuit for spends, or
   the general zkPVM made to fit phones?
6. **The root space:** should Virto's governance be the registry's only
   governor at first, and what should trigger moving it to a collective
   of spaces?
7. **Credentials:** which facts matter most to carry across spaces
   first (reputation, balances, membership, humanity)? They shape the
   first attestable kernels.
8. **Kreivo:** should a Kreivo pass holder be able to bring their pass
   into a VOS space (an authenticator that proves control of a pass), or
   start fresh?

## 15. Proposed staging

1. **This design, over a few rounds,** with a second opinion (Fable)
   on each draft.
2. **A review of cipher-clerk** against §13, before slice 5.
3. **First build:**
   - identities, authenticators and origins in a space;
   - guards on methods, with today's roles as one kind;
   - device-signed sessions.
   - It gives tiers S and X their everyday authority, independent of
     proving.
4. **With slice 5's prover:** anchors on JAM, attestable statements,
   credentials, nullifiers, and anonymous origins.
5. **Tier O,** once a device prover exists, with cipher-clerk's private
   payments as its first actor.
6. **The registry and the root space,** when spaces need to find each
   other, possibly alongside step 4.
