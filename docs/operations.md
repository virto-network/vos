# Operating a space's nodes

How an operator reaches a node, replaces one, and what an operator does
about a space's anchors at its venue (the protocol is `design/proving.md`
§7; the venue's calls are `design/spaces-pallet.md` (Kreivo) and the JAM
statements service's controls) and about its gateway's onion service.

## Reaching a node

- A node serves no HTTP: its binary API alone (`design/node-api.md`), on
  a unix socket, `api.sock` in its data directory unless its settings
  name `api_socket` (mode `api_socket_mode`, 0660 by default), and over
  QUIC when they name `api_listen`, to the client keys `gateways` lists.
  Firewall `api_listen` to the gateways and drivers.
- An operator's commands are signed with an operator key the node lists:
  `operator.key` in its data directory, listed unless `local_operator =
  false`, and the keys `operators` names. On the node's host,
  `vos agent create --data DIR` reaches the socket in `DIR` (`--node
  unix:PATH` reaches one `api_socket` names elsewhere), signing for
  the node whose key `DIR` holds; with `--node quic://HOST:PORT --api-key
  FILE` it reaches that node's QUIC instead, as a client key `gateways`
  lists, pinned by the same key.
- Clients over HTTP, and s4's SSH, reach a space through a gateway
  (`vos-gateway`), which holds no authority: an operator's route through
  it carries the operator's signed envelope in its `Authorization`
  header, and no token admits one. A space file's last column is each
  node's contact, which redirects carry: its gateway's URL, or its API's
  `quic://` address.
- A node keeps each operator command's nonce until two minutes past its
  expiry, and then the latest expiry it forgot (the floor), for good: a
  command expiring no later is refused `Expiry`, so a replay is refused
  even under a clock stepped back. A node whose clock ran ahead, and
  forgot nonces while it did, refuses every operator command once its
  clock is set right, until real time passes the floor (it warns at its
  start); the reads (`Stats`, `Status`) still answer. Keep the node's
  clock synchronized.
- Every node of a space spreads its groups' frames over the same number
  of streams a peer, `peer_lanes` (1,024; the settings file names none,
  an embedder's `Config` may). A node whose pair heartbeat names other
  lanes is refused whole by its peers, and refuses them: each logs a
  warning naming the peer and both values when it first hears them, and
  counts every frame dropped as `OtherLanes`. Run one release, or one
  `peer_lanes`, on every node; a node set right is taken again at its
  next heartbeat.

## The node key is the anchor key

- A node signs its space's anchors with its node key, the ed25519 key its
  store made at its first run (`vos node info` prints its public half).
  There is no other anchor key and no rotation.
- A founding node's key is listed at the venue by the registration. Any
  other node's key is listed by the space's controller (Kreivo's
  `add_authority`, paired with the node's account; the JAM service's
  `AddKey` control).
- Only a node whose key the venue lists replicates the space's
  representative: adding another is refused (`CannotRun`). A node knows
  the listing from its venue client's reads, made on the client's own
  thread a few seconds apart: until the client has read the space after
  a start, it lists no key, and creating or adding the representative
  there is refused the same way. Create it once the client has read the
  space, a few seconds after the node starts, and add again after a
  refusal.

## Replacing a node

A lost or compromised node key is answered by replacing the node, never
by changing its key:
1. start the new node, with a store of its own;
2. have the controller list the new node's key at the venue;
3. replace the old node by the new one among each agent's replicas, the
   representative's first (`vos agent replace --agent A --remove OLD
   --add NEW`, at each agent's leader);
4. have the controller remove the old node, in one sitting: on Kreivo,
   its authority (`remove_authority`, which removes the key paired with
   it), then any key left listed (`remove_anchor_key`); on JAM, its key
   (`RemoveKey`). Between the two Kreivo calls the old node's key is
   listed while its account is no authority: the venue refuses its
   anchors, and its client sends no more until the listing changes.

The replacement moves every replica the node held, not only the
representative's.

**A restored backup or a cloned store counts as a compromised node key.**
Two processes signing with one key, or a node resumed from an older copy
of its store, can sign two roots for one window, and the venue ends the
space for that. Never run a node from a copy of another's store: replace
the node, as above, before anything else (and before re-founding a space
that ended for it, or the new space inherits the fault).

## The representative's alerts

The representative's leader logs each, once a leadership (a window's
stop once), and keeps the latest (`Node::anchor_alerts`):
- **unlisted, handed off:** the venue does not list this node's key; the
  leadership moved to a replica whose key it lists, which anchors. List
  this node's key again, or replace it.
- **unlisted, waiting:** no replica's key is listed: nothing is anchored
  until the controller lists one. The leader checks every 2 s and hands
  off as soon as a replica is listed; a node hands off at most once a
  window of the space's clock, so a handoff that failed (its target down)
  is tried again in the next window.
- **evidence:** the venue held another root at a window, a quorum of the
  replicas held this node's row, and its anchor went as the
  equivocation's evidence, which ends the space (below).
- **stopped:** the space is blocked by the venue's governance, or ended
  by an equivocation (after an evidence alert when this node sent it). A
  blocked space anchors again once unblocked; an ended one never does.
- **never:** the venue will never take a window's anchor (too old, behind
  the space's last window, a signature it refuses), or the window aged
  unsent (an error). A window before the space's registration is routine,
  logged as a warning. Statements over that window's root are refused.
- **divergent replicas:** the venue holds another root at a window, and a
  replica of the representative, named with the root it holds, holds
  another row of it than the leader's. The majority decides, so a
  minority's dissent alone never holds the evidence back: with a quorum
  holding the leader's row the evidence goes all the same; without one, nothing is sent and the leader asks again every 2 s. The named
  root tells which side is wrong: equal to the venue's held root, that
  replica (or a fork of it) is the equivocator, its key compromised;
  equal to neither, it is an apply bug, a cloned store or a compromise.
  Either way, replace that replica.

## Which windows are anchored

An agent cuts its state, and reports its root to the representative,
only at a window a read of it waits on; the representative anchors only
the windows some agent reported, so a quiet space anchors nothing and
pays no fee. An issuer whose verifiers demand a recent root has its agent
report every window, and every window it reports is anchored:

    vos agent reports --data DIR --agent A --every true

(`--every false` goes back to the windows its reads wait on.) The issuer
must be an agent other than the representative: the representative's own
cuts carry no report of it, so a window only it saw is not anchored. A read whose window's close does
not come by `B_{w+2}` fails `NotClosed`; its caller asks again.

## A row that does not decode

A row of a window's close that does not decode (an agent's report mark,
the representative's close mark or its last report of an agent, a held
close) is moved aside under the agent's quarantine rows with its bytes,
and the batch goes on as if it were absent; every replica's apply logs it
at error level. The rows are kept for the operator to read; the next
report or close writes the row afresh.

## The onion service

A space's gateways serve the same SSH on an onion, and nothing else: no
HTTP. The file must name an SSH port (`ssh`) for its `[onion]`
(`design/light-node.md` §6.1, `design/node-api.md` §6). Requests that
came through it carry the onion's mark, which a node reads for an
onion-only agent and for the space's own `onion` setting (`"any"`,
`"anonymous"` for its proven calls only through the onion, `"all"` for an
onion-only space; set it alike on every node of the space).

- **arti in process**, the onion's one host (a gateway built with the
  `tor` feature):

  ```toml
  [onion]
  state = "/var/lib/vos-gateway/arti/state"
  cache = "/var/lib/vos-gateway/arti/cache"
  key = "/var/lib/vos-gateway/onion.key"   # made if missing
  ```

  The gateway prints `onion <address>` and `onion key <hex>` at start.
  Full vanguards are always on. `pow = true` needs a gateway built with
  `tor-pow`; no arti release has declared its service-side PoW ready, so
  it is off by default. An optional `arti = "…/arti.toml"` names an arti
  client configuration to start from (a private Tor test network's
  authorities and fallbacks, say; a key arti does not know is refused, not
  ignored); the section's state, cache and full vanguards still apply over
  it.
- **Caps:** each circuit counts as an address (4 connections, 16
  requests in flight over them, 20 requests a second, a burst of 40, 8
  streams at once); 1,024 circuits at once; 16 proven calls in flight
  through the onion, 2 a connection, 4 a circuit, one of a circuit's
  waiting for a place among the onion's at a time; an agent's calls from
  one circuit 4 a second, a burst of 16. Each is a key of `[onion]`
  (`circuit_connections`, `circuit_in_flight`, `circuit_rate`,
  `circuit_burst`, `circuit_streams`, `circuits`, `proven`,
  `proven_per_connection`, `proven_per_circuit`,
  `proven_waiting_per_circuit`, `agent_rate`, `agent_burst`);
  `circuit_streams` from 1 to 65,535 and `circuits` at least 1, or the
  gateway does not start. A clearnet address's requests in flight are
  `per_address_in_flight` (64).
- **The onion's SSH:** with an SSH port, the onion's port 22 serves the
  same screens (`vos-gateway`'s placeholder, or an application's built on
  its library) and `vos-api` subsystem, under the same `ssh_host_key`: the key the onion set lists
  for that onion. Its screens' own host-service calls pass no per-circuit
  limit, only the server's bound per session. The onion's SSH server
  holds at most `ssh_connections` connections in all (`[onion]`, 128 by
  default; the clearnet SSH port's is the top-level `ssh_connections`),
  each given 30 s to authenticate, and has no idle close of its own. That
  number is the onion's capacity: a phone in the foreground keeps four to
  six connections open (its feed, its spare, its screens, its member's
  and personal agent's), so 128 serves about 25 phones at once; raise it
  with the members a gateway serves.
- **Key files:** the gateway's key, the onion's key and an application's
  key (`seed` files in hex) are made `0600`; one its group or others may
  read or write is refused at start (`chmod 600` it).
- **The onion set:** the registrar sets the space's onions in the
  credential actor (`set_onions`, each onion's key and its SSH host key),
  which devices read (`onions`). Set it again when a gateway's onion
  changes.
- **Every node an upstream:** with `space = "<the space file>"`, a
  gateway starts only if each node of the space is among its `nodes`. A
  home's gateways must list every node.

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
- the credential actor (`vos-credentials`, `design/identity-and-authority.md`
  §6) is installed again with the same handle, and its tree re-seeded from the ended space's `member`
  digests, with no member action;
- the Clerk's pair commitments with every counterparty reset.
