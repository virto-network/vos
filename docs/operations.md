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

### Local system Agent host

Enable the Agent-native Local journal host only with both independent inputs:

```bash
vosx space up team \
  --agent-root-pins /etc/vos/spaces/team.root-pins \
  --agent-authority-socket /run/vos/agent-authority.sock
```

The pins file is the bounded canonical `RootAnchorPins` wire, not TOML or hex.
Pass its absolute canonical path; it must be a regular non-symlink file outside
the space data directory and its embedded space must exactly match the space
being booted. Provision it independently of the socket authority. In
particular, never generate the configured pins from the archive response being
verified.

The socket authority owns the durable, provider-first system-genesis archive.
It must remain available for every daemon restart once a native Agent
generation exists. Back up and restore that external archive under the
authority operator's procedure; it is intentionally not copied into a VOS
space backup. An unavailable, conflicting, corrupt, or mismatched archive
aborts startup before the Local Agent journal is opened. A configured authority
may report no archive only while no native `.agent`, `.agent-lock`, or retired
`.agent-image` generation exists; exact empty-host scope/lock metadata alone is
allowed before the first provider-first Create.

Native journals live under `<space-data>/agents/<full-agent-id>.agent` with a
sibling `.agent-lock`. The stable host lock is
`$XDG_CONFIG_HOME/vosx/locks/<space-id>.agent-host.lock` (or the corresponding
home-directory fallback), outside the replaceable space tree. The full Ed25519
identity decoded once from `<space-data>/node.key`
binds both libp2p networking and Local Merge records. Non-Ed25519 node keys are
rejected whenever this host is enabled.

This is a clean generation cutover. `.agent-image` files are retired and are
never opened or migrated. If the two Agent flags are absent, `space up` keeps
the legacy Service behavior only when no `.agent`, `.agent-lock`,
`.agent-image`, or Agent-host scope residue is present; finding any such state
fails closed and requires explicit operator configuration or removal after an
independent archival decision.

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

Each member may have 32 live credentials and may issue 256 credential
identities over the lifetime of one authority installation. Revoked identities
remain as bounded tombstones so an old bearer can never be activated again.

## Backup and restore

Stop the local daemon before backup:

```bash
vosx space backup team /safe/team-backup
vosx space restore /safe/team-backup --data-dir /srv/vos/team
```

The backup is a self-contained directory for the space-owned state, with a
signed-content manifest, service images, local databases, private side stores,
node identity, and the required blob cache. Restore verifies every file before
replacing anything. A configured system-Agent genesis archive and its
independent root-pins file are authority-owned external inputs and must be
backed up separately as described above.

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

The standard Agent execution profile uses the same fail-closed rule. Agent
Actor and AgentRuntime packages from the retired `standard-gas-r01` and
`standard-gas-r02` generations cannot be opened by an `r04` host. Generation
`r02` introduced the full v0.8 reorder-buffer scheduler, full-Ψ deblob/entry
failures, and sign-extended 64-bit `ecalli` identifiers. Generation `r03`
additionally binds exact durable terminal and execution-error outcomes to the
authenticated invocation ownership and acknowledgement protocol. Rebuild
those packages and recreate local development Agent images. The related
lifecycle wire first moved from
`vos-agent-runtime-abi-20260829r1` to `vos-agent-runtime-abi-20260829r2`, then
to `vos-agent-runtime-abi-20260831r3`, `vos-agent-runtime-abi-20260831r4`,
`vos-agent-runtime-abi-20260831r5`, and now
`vos-agent-runtime-abi-20260831r6`. Generation r3 binds Suspend and Resume
authority to the actor's exact expected deployment, so a receipt prepared
before an actor upgrade cannot mutate its replacement. Generation r4 makes
the three actor-state lanes independently sparse, binds their entries to a
per-install state generation, and scopes retained invocation results and
acknowledgements to Ordered, Merge, or replica-local execution. Invocation
authorization, AGEX/AGIR messages, replies, and retained results all bind the
same nonzero incarnation. Callers obtain that guest-derived value from
`AgentDriver::inspect_actor` or a validated paged directory inspection; it
must not be inferred from deployment metadata. Generation r5 signs aggregate
catalog resource ceilings into the runtime package and enforces them over the
deduplicated runtime-package plus actor package/schema/policy closure. Every
reference is capped at 8 MiB, the Standard closure at 12,289 unique references
and 64 MiB of referenced content, and a hash presented with inconsistent
lengths is rejected. Generation r6 adds the replay-authenticated journal
generation/admission context and the root-pinned live system-authority Control
state. Finalize and committee-rotation commands execute deterministically in
the guest, but only independently authenticated replay may persist their
history plans or mint post-publication authority. An r6 host deliberately
rejects r1/r2/r3/r4/r5 runtime packages and persisted Agent images; rebuild the
runtime and actor packages and recreate those images. The actor ABI itself
remains unchanged. This cutover does not change the frozen Service execution
identity or artifacts.

Portable invocation continuations now use kernel snapshot version 5, which
preserves sparse IPC DATA mappings exactly. Before upgrading a host, let every
in-flight version-4 continuation drain; any remainder must be restarted from
its durable invocation input. Version-5 hosts deliberately reject version-4
snapshots and provide no compatibility decoder.

## Release artifacts

```bash
just package-production-release
cargo run -p vosx -- release verify target/production-release
```

Release verification rejects symlinks, special files, extra files, digest
mismatches, and non-reproducible PVM output. The bundle contains the consensus
service, canonical space authority, and standard multi-actor runtime.
