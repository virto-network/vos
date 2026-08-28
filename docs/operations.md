# Operations

## Node lifecycle

```bash
vosx space new team
vosx space up team \
  --service-pvm services/vos-service/vos-service.pvm \
  --production-trust-socket /run/vos/trust.sock
vosx space info team
```

Production roots also require a configured trust provider. Route publication
happens only after the local service has caught up, validated its trust policy,
and—when applicable—proved committed final Raft membership.

## Built-in ingress

HTTP listeners are configured per node in `<space-data>/local.toml`. Issue and
revoke their protocol-neutral credentials through the canonical authority:

```bash
vosx space access team issue --expires 24h
vosx space access team issue-ssh ~/.ssh/id_ed25519.pub --expires 30d
vosx space access team list
vosx space access team revoke <full-credential-id>
```

The authority binds each credential to a stable member. Owners can revoke a
credential by its full ID; prefix lookup and listing require
credential-management authority. Add `--subject <hex>`
only when an administrator is adding a device for someone else. HTTP actor
calls and SSH shell actions both pass the actor's signed method policy and the
member's live capability decision. See [HTTP ingress](http-ingress.md) and the
[SSH space shell](ssh-ingress.md).

## Backup and restore

Stop the local daemon before backup:

```bash
vosx space backup team /safe/team-backup
vosx space restore /safe/team-backup --data-dir /srv/vos/team
```

The backup is a self-contained directory with a signed-content manifest,
service images, local databases, private side stores, node identity, and the
required blob cache. Restore verifies every file before replacing anything.

A restored replicated node may be behind. This is expected: keep the same node
identity and replication incarnation, reconnect it, and wait until its durable
applied cursor reaches the current cluster commit before relying on local
reads. Never restore one identity onto two live machines.

## Raft membership

Add a prepared replica before promoting it. Remove a voter only through the
replacement workflow; the retiring replica stays available until the final
configuration and retirement acknowledgement are durable. Status is steady
only when the active configuration index is committed and no joint membership
remains.

## Upgrades

An upgrade is a signed actor transition, not a catalog rewrite. Stage the full
replacement package on every voter, propose the upgrade, wait for application,
then update the catalog with compare-and-swap. Exact retries recover the
already committed result.

Host state-machine changes use a separate identity in every new Raft
application entry and applied snapshot. Before replacing binaries, pause
ingress and transport acknowledgement and verify `last_applied ==
commit_index` on every voter. Replace the complete voter set, then resume
traffic. A host with a different state-machine identity cannot apply a new-format entry: it rejects the
entry before guest execution and leaves its applied cursor unchanged. This
turns a mixed deployment into an explicit unavailable replica instead of two
replicas silently committing different service images.

The role authority's replication incarnation is fixed when a space is
created. Rebuilding or upgrading its signed package does not derive a new
incarnation.

Platform identities are clean compatibility boundaries. This repository is
not released yet, so the capability-role and SSH-shell cutover deliberately
does not retain a decoder or conversion bridge for earlier development spaces.
Recreate those spaces from packages and application exports.

## Release artifacts

```bash
just package-production-release
cargo run -p vosx -- release verify target/production-release
```

Release verification rejects symlinks, special files, extra files, digest
mismatches, and non-reproducible PVM output.
