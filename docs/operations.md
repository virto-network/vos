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

## Release artifacts

```bash
just package-production-release
cargo run -p vosx -- release verify target/production-release
```

Release verification rejects symlinks, special files, extra files, digest
mismatches, and non-reproducible PVM output.
