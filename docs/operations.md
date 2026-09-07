# Operations

## Node lifecycle

```bash
vosx space new team
vosx space up team
vosx space info team
vosx space down team
```

The standard AgentRuntime and system actors are embedded and protocol-pinned;
`space up` accepts no external execution-program selection. Startup opens the
full Ed25519 node identity once and uses it for both transport and Agent
provenance. Symlinks, hard-link aliases, noncanonical encodings, non-Ed25519
keys, wrong owners, and group/other-readable key files are rejected.

Route publication happens only after durable Agent state, authority evidence,
profile membership, and replication cursors have been reconciled. A corrupt,
foreign, rolled-back, or partially published generation fails before ingress
is exposed.

## Identity and credentials

Nodes, Principals, and Credentials have separate lifecycles. Use full IDs for
security decisions; prefixes are display conveniences only.

```bash
vosx whoami
vosx space access team issue --expires 24h
vosx space access team issue-ssh ~/.ssh/id_ed25519.pub --expires 30d
vosx space access team list
vosx space access team revoke <full-CredentialId>
```

Each credential is bound to one Principal by the system authority. Revoking a
credential does not remove a replica Node, and adding an SSH key never admits
that client as a replica. Node enrollment authenticates the full transport
identity and, for Private Agents, the separately signed X25519 key.

## Agent inventory and lifecycle

```bash
vosx agent list team
vosx agent create team board --profile shared
vosx agent create team companion --profile private
vosx agent create team scratch --profile local
vosx agent show team/board
```

Profiles are immutable. Names may change and can be ambiguous across profile
directories; use the full `AgentId` whenever a name is not unique. The system
Agent is listed as `system`, but cannot be removed or incompatibly replaced.

Shared replica-set changes preserve one membership definition for every lane.
Prepare and catch up a new replica before promotion. During voter replacement,
retain the departing voter until the joint configuration and final
configuration are durably committed. A replica is ready only when its applied
cursor reaches the current commit and no unresolved joint membership remains.

## Actor and runtime upgrades

```bash
vosx actor install team/board board.vos --name board
vosx actor upgrade team/board/board board-new.vos
vosx actor suspend team/board/board
vosx actor resume team/board/board
vosx actor remove team/board/board
```

An upgrade is a signed Agent transition. Distribute and verify the complete
replacement package before proposing it. Exact retries recover the already
committed result; they never execute a second upgrade. Catalog alias updates
occur only after the Agent transition is final.

Runtime upgrades use the mandatory management ABI and an explicit migration
policy. Pause new work, drain or persist continuations, verify every replica
has applied through the same committed boundary, and only then activate the
replacement. A runtime with a different state-machine identity rejects an
entry before execution rather than attempting mixed-version interpretation.

The current generation provides no migration decoder for older packages,
state images, snapshots, proof records, or backup formats. Rebuild packages
and recreate development Agents from authenticated application exports.

## Private membership and recovery

```bash
vosx agent invite-node team/companion --node <full-NodeId>
vosx agent revoke-node team/companion --node <full-NodeId>
vosx agent recover team/companion --recovery-kit /safe/companion.recovery
```

Invitation requires an authority binding between the owner Principal, exact
Node transport identity, and that Node's signed X25519 public key. Owner and
data keys are sealed independently to the admitted Node.

Revocation removes one exact Node and commits a fresh owner/data epoch before
later writes are accepted. It protects future state; it cannot erase data the
Node already observed. Keep the offline recovery signing and encryption halves
outside every active Node. Recovery validates all source archives before
mutation, deterministically reconciles compatible ciphertext, supersedes old
control heads, rotates both keys, and admits the replacement Nodes.

Private synchronization rejects an unknown or revoked peer before reading or
transmitting state. Transfer is bounded and chunked, and every object remains
authenticated ciphertext on disk, in frames, snapshots, and backups.

## Backup and restore

Stop the node before taking or restoring an offline backup:

```bash
vosx space down team
vosx space backup team /safe/team-backup
vosx space restore /safe/team-backup \
  --node-key /safe/team.node-key \
  --data-dir /srv/vos/team
```

The node key is never placed in the archive. Retain it separately with mode
`0600`; restore requires the exact key whose public identity appears in the
manifest. Never activate one node identity on two machines at the same time.

The clean backup format contains authenticated portable profile exports,
content-addressed packages, encrypted Private material, and public recovery
metadata. It excludes active unwrapped keys, plaintext Private state,
credentials, endpoint files, and node-local policy. Creation and restore use
unpublished sibling directories; every manifest entry is bounded and verified
before activation. Existing state is replaced only with `--replace` and is
renamed aside rather than deleted.

A restored Shared replica may be behind. Reconnect it under the same exact
Node identity and wait for its durable applied cursor to catch up before using
local reads. A Private restore additionally correlates the recovered control
head with fresh authority evidence before synchronization.

## Ingress

HTTP routes use:

```text
/<agent>/<actor>/<method>
```

SSH navigation follows Space → Agents → Actors → Methods. Both surfaces show
the profile, method lane, observation freshness, attestation policy, and
idempotency requirement. They authenticate a Credential into a Principal and
carry Node provenance separately when forwarding. Both submit the same
canonical Agent invocation; neither owns a private execution path.

For retried mutations, retain and reuse the invocation/idempotency key until a
terminal result is acknowledged. A timeout is not evidence that execution did
not commit. Queries report the Linear revision, Merge frontier, and Local
revision observed.

## Proof production

Attested execution is tentative until the nested execution transcript has
been proved, producer-signed, and independently verified. Publication commits
the proof record and its exact transition atomically. A crash before that point
cannot expose the state; an exact retry reproduces the same proof identity.

Producer-private witnesses belong in a protected node-local sidecar. They must
not appear in Agent state, Raft entries, Merge frames, public proofs, logs, or
backups. Followers verify the public proof, runtime and actor identities,
method and mode, work and transition, and before/after lane commitments without
access to the witness.

## Release artifacts

```bash
just package-production-release
vosx release verify target/production-release
```

The release directory contains exactly the standard AgentRuntime, authority
actor, catalog actor, and strict manifest embedded by the checked `vosx`
binary. Bundling accepts no external program path. Verification rejects the
previous release generation, symlinks, special files, unexpected entries,
digest or program-identity mismatches, and any artifact that differs from the
binary's protocol pins.

Before distribution, run the workspace checks, Clippy, formatting, docs,
examples, all feature combinations, standard-program conformance and parity,
hostcall allowlist inspection, reproducibility tests under clean homes and
target directories, profile restart/failover/recovery suites, and physical
HTTP and SSH idempotency tests.
