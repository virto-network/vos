# Workstream C — clerk/settlement tracking notes

Working notes for the clerk-settlement branch (federation-showcase.md
Track S: G6 → S1 → S2 → S4 → S5 → S6). Not a design doc — a running
record of decisions and deferred work whose rationale doesn't belong in
code comments.

## G6 — Raft caller-identity gate (RESOLVED: node-peer grants are the pattern)

**Question.** A `clerk-ledger` runs `Consistency::Raft` across a bank's
nodes; its money-path mutators are `#[msg(role = Operator)]`. When such a
mutator reaches the Raft leader from another node — either a follower's
in-process agent auto-forwarding a refused write
(`agent_forward_to_raft_leader`, `vos/src/node.rs`) or any cross-node
invoke — the leader attributes the caller to the **forwarding/peer node's
PeerId**. The in-process `Caller::System` / `Caller::Actor` identity that
bypasses role gates is *lost* the moment the invoke leaves the node. So:
does the existing node-peer grant path satisfy the Operator gate, or is a
new mechanism (a System-relayed forward) required?

**Answer: node-peer grants work; no new mechanism.** The leader resolves
the caller's space role from its **local** space-registry
(`lookup_caller_role` → `peer_role`). Granting the voter node's own PeerId
`AUTH_ROLE_ADMIN` (space `Admin`, which the `CLERK_LEDGER_SPACE_ROLE_MAP`
maps to `ClerkLedgerRole::Operator`) makes the forwarded/cross-node write
pass. `AUTH_ROLE_DEVELOPER` would also map to `Operator`; `Member` would
not. This is the "chronos lesson" already documented at
`vos/src/node.rs`'s `agent_forward_to_raft_leader`.

Proven by `raft_clerk_ledger_operator_gate_under_leader_forward`
(`vos/tests/elf_integration.rs`): ungranted node peer → `Forbidden`;
granted node peer → `bootstrap`/`create_account`/`apply_transfer` commit
through the leader and both replicas converge on one state root; a
follower restart re-converges.

**Consequences this shapes:**

- **Manifests (S5).** `clerk-ledger` is `consistency = "raft"`. The
  space-registry that resolves the grant must be **CRDT-replicated across
  the bank's nodes** so the grant is present on whichever node holds
  leadership. (The grant is anchored on one node and converges; the test
  asserts convergence on both replicas before driving the gated writes.)
- **Grant script (E/S7).** Grant **every voter node's own peer**
  `Admin` on the bank's space — not only the operator's CLI peer. A write
  that lands on / forwards through a node authenticates as *that node's*
  peer.
- **clerk-settle (S1).** `register_bank` / `settle_window` are
  Operator-gated on a Raft venue and inherit the same rule. The demo
  targets the venue **leader** directly for these (via `raft-status`), but
  the venue's node peers must still be granted `Admin` so a co-located
  agent's forward (or a leadership flip mid-call) doesn't strand the write.
  `submit_claim` stays an OPEN handler (auth = the bank's claim signature),
  so it is unaffected.

## Handler arg typing (G25 status)

G25 (custom rkyv structs as `#[msg]` args) has **not** landed on master as
of the branch point (`macros-typed-args` sits at the same commit as
master). New handlers on `clerk-settle` and `clerk-bridge` are therefore
written in the `Vec<u8>` + manual-decode idiom, matching the existing
clerk actors.

**Retype TODO (after G25 lands):** replace the `Vec<u8>` args below with
typed rkyv structs / `[u8; N]` and drop the `decode_or_bad_input!`-style
decoding. Call sites to revisit will be listed here as the handlers land.
