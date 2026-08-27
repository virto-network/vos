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

## HTTP ingress

HTTP listeners are configured per node in `<space-data>/local.toml`. Issue and
revoke their protocol-neutral credentials through the canonical authority:

```bash
vosx space access team issue --role member --expires 24h
vosx space access team list
vosx space access team revoke <credential-prefix>
```

Only `/__status` is anonymous. Schemas and OpenAPI require Member, metrics
requires Admin, and actor calls also pass the actor's signed method policy.
See [HTTP ingress](http-ingress.md) for listener and TLS configuration.

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
traffic. A predecessor host cannot apply a new-format entry: it rejects the
entry before guest execution and leaves its applied cursor unchanged. This
turns a mixed deployment into an explicit unavailable replica instead of two
replicas silently committing different service images.

The role authority's replication incarnation is fixed when a space is
created. Rebuilding or upgrading its signed package does not derive a new
incarnation.

The HTTP-ingress cutover carries one explicit migration bridge for spaces
created by the immediately preceding canonical release. The daemon embeds
that release's exact service guest and selects it only when an installed
package names its ProgramId. Start the new daemon, run the ordinary
guest-owned `space upgrade` for `space-authority`, and restart once the
catalog compare-and-swap completes. The authority actor and signed contract
advance; its service identity, service guest, and replication incarnation do
not. Fresh spaces use only the current guest. No arbitrary historical guest
or contract is accepted. The release gate opens a production Raft image and
log created by the predecessor release, performs this catalog cutover, invokes
a newly added access method, acknowledges it through the predecessor guest,
and proves its exact result still recovers after restart.

## Release artifacts

```bash
just package-production-release
cargo run -p vosx -- release verify target/production-release
```

Release verification rejects symlinks, special files, extra files, digest
mismatches, and non-reproducible PVM output.
