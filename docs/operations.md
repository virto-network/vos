# Operating a space's nodes: anchoring

What an operator does about a space's anchors at its venue (pin D′,
`design/slice-7-mobile.md`). The protocol is `design/proving.md` §7; the
venue's calls are `design/spaces-pallet.md` (Kreivo) and the JAM
statements service's controls.

## The node key is the anchor key

- A node signs its space's anchors with its node key, the ed25519 key its
  store made at its first run (`vos node info` prints its public half).
  There is no other anchor key and no rotation.
- A founding node's key is listed at the venue by the registration. Any
  other node's key is listed by the space's controller (Kreivo's
  `add_authority`, paired with the node's account; the JAM service's
  `AddKey` control).
- Only a node whose key the venue lists replicates the space's
  representative: adding another is refused (`CannotRun`).

## Replacing a node

A lost or compromised node key is answered by replacing the node, never
by changing its key:
1. start the new node, with a store of its own;
2. have the controller list the new node's key at the venue;
3. replace the old node by the new one among each agent's replicas, the
   representative's first (`vos agent replace --agent A --remove OLD
   --add NEW`, at each agent's leader);
4. have the controller remove the old node's key (and, on Kreivo, its
   authority).

The replacement moves every replica the node held, not only the
representative's.

**A restored backup or a cloned store counts as a compromised node key.**
Two processes signing with one key, or a node resumed from an older copy
of its store, can sign two roots for one window, and the venue ends the
space for that. Never run a node from a copy of another's store: replace
the node, as above, before anything else (and before re-founding a space
that ended for it, or the new space inherits the fault).

## The representative's alerts

The representative's leader logs each as an error, once, and keeps the
latest (`Node::anchor_alerts`):
- **unlisted, handed off:** the venue does not list this node's key; the
  leadership moved to a replica whose key it lists, which anchors. List
  this node's key again, or replace it.
- **unlisted, waiting:** no replica's key is listed: nothing is anchored
  until the controller lists one. The leader tries to hand off again
  once a window.
- **stopped:** the space is blocked by the venue's governance, or ended
  by an equivocation. A blocked space anchors again once unblocked; an
  ended one never does (below).
- **never:** the venue will never take a window's anchor (too old, behind
  the space's last window, a signature it refuses), or the window aged
  unsent. Statements over that window's root are refused.
- **divergent replicas:** the venue holds another root at a window, and a
  replica of the representative holds another root of it than the
  leader's. This is an apply bug or a cloned store, not a theft: the
  leader sends nothing, so the space is not ended for it. Stop the
  replica that differs and replace it.

## An ended space

An equivocation's evidence ends a space at its venue for good: its roots
are refused, it never anchors again, and the venue keeps its record, so
the same genesis never registers again. The space re-founds under a new
genesis, so a new `SpaceId`:
- the nodes found the new space, and register it at the venue;
- the sovereign account's funds leave by the controller's
  `dispatch_as_sovereign`, which stays callable on an ended space (its
  existential deposit stays); the registration deposit is released to it
  when the space ends;
- the credential actor (pin G, from step 7.9) is installed again with the
  same handle, and its tree re-seeded from the ended space's `member`
  digests, with no member action;
- the Clerk's pair commitments with every counterparty reset.
