# Production v2 release operations

This runbook covers the artifacts and offline state that an operator needs to
move a production v2 node without changing protocol identity. It is deliberately
conservative: an operation that would rewrite a sealed identity without a
guest-owned transition is refused.

## Release artifact set

The committed service PVM is reproduced with:

```sh
just build-vos-service
```

That command does not compile moving HEAD. It exports the immutable source
revision and invokes the date-pinned host/guest toolchains recorded in
`support/v2-production-artifacts.toml`, runs that revision's transpiler, checks
the fresh PVM digest and ProgramId, and requires it to match the committed PVM
byte-for-byte. The fresh output is
`target/pinned-v2-artifacts/vos-service.pvm`. A clone must therefore retain or
fetch that revision. Use `just build-vos-service-candidate` for current sources
when preparing an explicit identity migration.

Clerk has two distinct identities at release time. Its ProgramId, DeploymentId,
and Task hash bind reproducible package content. The outer `.vos` bytes also
carry the producer's key and deterministic signature, so they are intentionally
operator-specific rather than a repository-global digest. Select that signer
explicitly:

```sh
just build-clerk-v2-package /secure/operator/identity.key
```

The command does not consult or create an ambient XDG identity. Record and
publish the printed signed-package digest with the operator's release metadata;
the catalog thereafter retains those exact signed bytes. Test recipes instead
use a clearly labeled ephemeral signer and never treat their `.vos` as a
release artifact.

Reproduce the canonical ABI-17 authority, then package it with the committed
service:

```sh
just build-authority-release
just package-v2-production-release target/production-v2-release
cargo run -p vosx -- release verify target/production-v2-release
```

`build-authority-release` performs the checkout-independent canonical actor
build and requires the fresh PVM to equal the committed authority byte-for-byte.
The package command repeats that prerequisite before assembling the release.

The output directory contains exactly:

- `vos-service.pvm`, whose `ProgramId` must equal
  `VOS_SERVICE_PROGRAM_ID`;
- `space-authority.pvm`, whose bytes and `ProgramId` must equal the canonical
  ABI-17 authority identity; and
- `manifest.json`, which binds both file sizes, raw BLAKE2b-256 digests,
  program identities, the v2 ABI, store schema, and execution-semantics ID.

`vosx release verify` rejects symlinks, extra files, missing files, version
drift, and changed artifact bytes. Run it on the destination host after copying
the directory. Start the daemon with the verified `vos-service.pvm`; never
select a service PVM from an unverified build cache.

The authority PVM is included for disaster recovery and identity inspection.
Normal startup uses the copy embedded in the release `vosx` binary and verifies
the same ABI-17 digest during the binary build.

Before publishing the directory, run `just test-v2-release-operations`. The
gate consumes the packaged service in a real Local root backup/reopen and moves
a stopped production Raft voter through an offline archive into fresh machine
roots before requiring catch-up, a new election, and another commit.

## Host-private device signers

A v2 root whose local policy sets `device_secret = true` receives a
host-private CipherClerk signer through the Refine-only `DEVICE_SIGN`
capability. The daemon stores the 32-byte seed at
`v2-services/<root-service-id>.device-seed` with mode `0600`; actor memory,
service snapshots, and Raft entries contain only the public key and signature.
Existing seed paths must be regular, non-symlink files with exactly that mode
and length or startup fails closed. First creation writes and syncs a private
temporary file, atomically activates it, and syncs the containing directory
before exposing the root. The actor must pin and compare the returned public
key before accepting a signature. One Refine slice may request at most eight
signatures, each over at most 4 KiB.

For a Raft root, provision the exact same seed file on every voter before that
voter can become leader. A missing file is minted locally, which intentionally
creates a different identity and therefore fails an actor's public-key check;
it is not a distributed key-generation protocol. Offline space backup includes
this sidecar. Treat it like the node key and private-ingress store: encrypt the
archive, never run two restored copies of one voter, and verify the signer
public key before restoring traffic. CRDT roots reject this option.
Uninstall/reinstallation moves a retired root's seed into recoverable trash
with its image, Raft database, proofs, and private records. This removes the
seed from the active service directory, but an offline whole-space backup
recursively includes `trash/` and therefore retains retired seeds. Protect
those archives as containing both active and recoverable retired signer keys;
removing a retired seed from future backups requires an explicit,
irreversible trash-pruning decision by the operator.

## Move an existing voter to another machine

This is an identity-preserving machine replacement, not a Raft membership
change. It is safe while the other voters keep committing because the restored
node catches up through ordinary Raft log or snapshot transfer.

1. Confirm the remaining voters form a quorum and record
   `vosx space raft-status <space> <root>` for each Raft root.
2. Stop the source daemon. Do not start it again after copying its state.
3. Through a surviving voter, commit a fresh, application-visible marker after
   the source has stopped. Record both the marker and a survivor's resulting
   `commit_index` as `REJOIN_INDEX`. This is the cluster high-water the stale
   backup must reach; the stopped voter's own `commit_index` is not evidence of
   catch-up.
4. Create an offline archive while the daemon-held data lock is free:

   ```sh
   vosx space backup <space> /secure/offline/<space>.vos-backup
   ```

5. Copy the archive and a verified production release directory to the new
   machine. Treat the archive as secret: it contains the node identity,
   production policy, private ingress/proof/producer stores, and application
   state.
6. Restore into fresh data, config, and cache roots:

   ```sh
   vosx space restore /secure/offline/<space>.vos-backup --name <space>
   vosx space up <space> \
     --service-pvm /opt/vos-release/vos-service.pvm \
     --production-trust-socket /run/vos-authority.sock \
     --connect <surviving-voter-multiaddr>
   ```

7. Query `vosx space raft-status` against the restored daemon itself. This
   status is local and is not redirected. Require `last_applied >= REJOIN_INDEX`,
   `joint_old` to be absent, and `active_config_index <= commit_index`. Crossing
   `REJOIN_INDEX` is the local observation that the post-stop marker has been
   applied. Do not use an ordinary actor read as catch-up evidence because a
   follower may transparently redirect it. After this local proof, confirm the
   marker through the application and make a write through a different voter.

The archive preserves `node.key`, so the replacement has the same full Noise
`PeerId` and compact Raft slot. Running the source and replacement concurrently
would duplicate one consensus identity and is forbidden. To replace a voter
with a *new* identity:

1. enroll the new node as a voter and let it join every Raft root;
2. on the new node, require `joint_old` to be absent,
   `active_config_index <= commit_index`, and `last_applied >=
   active_config_index` for every root;
3. quiesce package publish/install operations and wait for the registry view on
   every connected operator node to contain the same old and replacement NODE
   bindings; the command scans one materialized catalog and must not race a new
   root installed from a lagging view;
4. while the old daemon is still online, run through any group member:

   ```sh
   vosx space members <space> remove-node <OLD_PREFIX> \
     --replacement <NEW_PREFIX>
   ```
5. only after the command reports success, stop the old daemon permanently.

The command signs each root's replication ID, complete registry-bound PeerIds,
compact slots, and current membership index with the operator identity. A
follower may relay that authorization but cannot invent or alter it. It first
demotes the old NODE row to observer so newly installed roots cannot enrol it,
but retains that exact PeerId binding and the retiring private Raft endpoint
while each existing group commits both the final membership and a second
consensus-visible confirmation that the retiring replica learned that
finality. It serializes each change with private-ingress admission, requires the replacement to be a
committed voter, and waits for a
committed final non-joint configuration plus its retirement confirmation
before moving to the next Raft root. Only after every installed Raft root has
retired the old slot does it remove the old NODE row from the registry. The
multi-root operation is deliberately
resumable rather than falsely atomic: if the command loses a reply or stops
halfway, rerun the same command while the old registry row still exists.
Completed roots return an idempotent terminal result; unfinished roots resume
joint consensus. Never remove the registry row manually first, because that
row is what authenticates the retiring slot during the transition.

## Canonical authority upgrades

The bundled ABI-17 `space-authority` PVM is a durable actor-program artifact.
Its package, deployment, and derived replication identity are pinned per
platform ABI because the package manifest also binds the service PVM, ABI, and
execution semantics. Rebuilding its source within one ABI produces an upgrade
candidate, not a replacement release blob:

```sh
just build-authority-upgrade-candidate
vosx space publish <space> space-authority:artifact-only \
  target/bundled-space-authority/space-authority.vos
vosx space upgrade <space> space-authority space-authority:artifact-only
```

Run the build/publish step with the immutable space-root identity; a package
signed by an ordinary administrator or voter is refused before `UpgradeActor`
is proposed.

Do not copy that output over `vosx/blobs/space_authority.pvm`. Ordinary signed
v2 Local and Raft roots use `vosx space upgrade`, which drives the guest-owned
transition before its catalog compare-and-swap. `space-authority` uses that
same transition with additional checks: both the installed and replacement
packages must be signed by the immutable space root and must preserve the
exact platform schemas, generated interfaces, role policies, Task dependency
surface, and Raft consistency. These are not CLI-only checks: the root driver
retains the immutable signer key and compact contract commitments and rejects
any raw Admin, System, or voter-delegated proposal that does not match them
before the Raft admission barrier and production verifier.

The migration is one canonical `UpgradeActor` request against the existing
Raft authority root. The command:

1. verify the signed candidate package and make its PVM available on every
   Raft voter;
2. resolve the authority actor and bind its current deployment/program as the
   expected pair;
3. obtain an exact linear read base after the current-term barrier;
4. obtain production authorization for the complete `UpgradeActor` bytes;
5. proposes the transition with the signed package and PVM in the ordered
   availability sidecar, then waits for its durable disposition;
6. compare-and-swaps the catalog only after the guest commits the exact actor
   deployment and program.

Within the same platform ABI, the authority service identity and replication
incarnation do not change.
Dependent roots remain bound to the frozen genesis service deployment while
the authority's guest-owned actor descriptor advances to the replacement
deployment. On restart, the daemon resolves that stable service binding and
uses the permanent upgrade record to validate the catalog's newer actor
package.

An ABI/store clean break is not an authority actor upgrade. It creates a new
canonical authority package, deployment, and auto-derived replication
incarnation even though the bundled actor PVM remains byte-identical. A space
sealed under ABI 16 must be operated with its ABI-16 release or cleanly
reinstalled for ABI 17; the daemon rejects the old cutover marker rather than
rewriting it. No in-place service-image migration across that boundary is
currently supported.

The ordinary-root command already implements the corresponding signed-package
availability, authenticated transition, catalog ordering, and exact retry
recovery. Guest Accumulate enforces the exact base, authenticated request,
replacement program availability, and the absence of continuations or pinned
authorized inboxes. A restarting voter recovers a catalog package from its
committed Raft log or installed snapshot even when the corresponding service
image had not applied the upgrade before the crash. If a survivor acknowledged
the upgrade but missed the leader's commit heartbeat, the exact
catalog-addressed package may also be recovered from its durable appended tail
solely to start Raft; only the later Raft commit index can authorize guest
application. Raft upgrades require the sealed production trust policy;
the process-local conformance allowlist is deliberately refused because it
cannot replay on followers. CRDT roots, roots exposing attested methods, and
changes which add or remove the root's role-authority requirement remain
unsupported. Those shapes need guest-owned binding migrations before an
in-place upgrade can be safe. Keep the bundled ABI-17 PVM unchanged within that
release line: it is the recovery/genesis artifact for ABI-17 spaces, not an
implicit upgrade channel.
