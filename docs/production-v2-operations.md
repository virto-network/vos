# Production v2 release operations

This runbook covers the artifacts and offline state that an operator needs to
move a production v2 node without changing protocol identity. It is deliberately
conservative: an operation that would rewrite a sealed identity without a
guest-owned transition is refused.

## Release artifact set

Package the committed canonical service with the frozen space authority:

```sh
just package-v2-production-release target/production-v2-release
cargo run -p vosx -- release verify target/production-v2-release
```

The output directory contains exactly:

- `vos-service.pvm`, whose `ProgramId` must equal
  `VOS_SERVICE_PROGRAM_ID`;
- `space-authority.pvm`, whose bytes and `ProgramId` must equal the frozen
  Batch 70 authority identity; and
- `manifest.json`, which binds both file sizes, raw BLAKE2b-256 digests,
  program identities, the v2 ABI, store schema, and execution-semantics ID.

`vosx release verify` rejects symlinks, extra files, missing files, version
drift, and changed artifact bytes. Run it on the destination host after copying
the directory. Start the daemon with the verified `vos-service.pvm`; never
select a service PVM from an unverified build cache.

The authority PVM is included for disaster recovery and identity inspection.
Normal startup uses the copy embedded in the release `vosx` binary and verifies
the same frozen digest during the binary build.

Before publishing the directory, run `just test-v2-release-operations`. The
gate consumes the packaged service in a real Local root backup/reopen and moves
a stopped production Raft voter through an offline archive into fresh machine
roots before requiring catch-up, a new election, and another commit.

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
with a *new* identity, first enroll and fully promote the new voter. Automated
removal of the old identity is not yet an operator surface; removing only its
registry row does not rewrite existing Raft configurations.

## Frozen authority upgrades

The bundled Batch 70 `space-authority` is a durable actor deployment. Rebuilding
its source produces an upgrade candidate, not a replacement release blob:

```sh
just build-authority-upgrade-candidate
```

Do not copy that output over `vosx/blobs/space_authority.pvm`. Ordinary signed
v2 Local and Raft roots may use `vosx space upgrade`, which drives the
guest-owned transition before its catalog compare-and-swap. The command still
refuses `space-authority`: its catalog deployment is also the stable trust
binding consumed by every dependent root.

The only valid authority migration is one canonical `UpgradeActor` request per
affected Raft authority root. A future authority-specific migration must
perform all of the following as one authenticated workflow:

1. verify the signed candidate package and make its PVM available on every
   Raft voter;
2. resolve the authority actor and bind its current deployment/program as the
   expected pair;
3. obtain an exact linear read base after the current-term barrier;
4. obtain production authorization for the complete `UpgradeActor` bytes;
5. propose the transition and wait for the final applied index on every voter;
6. verify the actor deployment, program, producer, and method policies from
   guest-owned state before distributing a release that expects the new
   authority.

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
application. Raft upgrades require the
sealed production trust policy;
the process-local conformance allowlist is deliberately refused because it
cannot replay on followers. CRDT roots, roots exposing attested methods, and
changes which add or remove the root's role-authority requirement remain
unsupported. Those shapes need guest-owned binding migrations before an
in-place upgrade can be safe. Until the authority-specific command and a
cross-version authority rehearsal land, the production procedure is to retain
the frozen authority and restore it from the verified release bundle.
