# The node's credential surface: security considerations

What a node's operators learn from the requests a member's device sends
for its credentials. It is descriptive, not a formal argument. The design
is `docs/design/identity-and-authority.md` (§6 the credential actor, §7
the threat model); what the device library holds is
`pvm/device/SECURITY.md`'s, and what a verified proof proves is
`pvm/proof/SECURITY.md`'s.

## What operators learn

`Anonymous` hides a member from the log's readers, from other agents and
from other members, not from the operators of the nodes and gateways that
serve its requests.

- **The path leak, reduced, not closed.** Asking the credential actor for
  `path(member)` tells the operators which member digest is online, and
  from which address. What they do not learn is when it proves:
  - the device library (`PathKeeper`) fetches its path apart from its
    proofs: when a `root()` answer has moved and on a timer of 30 s
    jittered uniformly between 15 s and 45 s, never because a proof is
    about to be made, on a connection of its own;
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
- **From a tree change:** every online member's library fetches its path
  when `root()` moves, so each enrollment or revocation shows which member
  digests are online then; the jitter spreads the fetches, it does not
  hide them. Syncing the tree is the later fix.
