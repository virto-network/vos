# Operations

## Current operator surface

The clean-cutover CLI is intentionally narrow:

```bash
vosx space new team
vosx space list
vosx space info team
vosx space up team
vosx space caps team
vosx space down team
```

`space forget` removes only a stopped local copy. It requires confirmation
unless `--yes` is supplied. `space up` accepts repeatable `--listen` and
`--connect` addresses and has a one-shot `--once` smoke mode.

On Linux the clean Local workflow also exposes `space create-local-agent`,
`space install-local-actor`, `space invoke-local` and exact retained-request
submission/recovery commands. Use each command's `--help`; these are not the
retired generic Agent/actor commands. An unknown top-level word is a usage
error, never a dynamic actor name. Ordinary Shared-Agent genesis/finality is
still unavailable. See [Getting started](getting-started.md) for Local setup
and [current status](agent-saga-status.md) for test evidence and release gaps.

`space invoke-local SPACE --intent PATH` consumes canonical ATQ1 bytes with a
stable invocation ID and operator origin; it is not a method-name/JSON command.
It authorizes, delivers and positively retires the exact intent.
`space invoke-local SPACE --resume` resumes the retained credential reservation
without reading a new intent. Lower-level `submit-agent-*` and
`continue-agent-invocation` commands operate on exact retained protocol stores;
they do not make arbitrary bytes valid. Deployment-scoped role administration
is exposed through `space set-actor-role` and retained admin commands.

Preserve operation stores on timeout or failure. An unsigned HTTP error is not
a signed outcome, and retrying with a new identity can create a different
operation. Server retention is bounded: a retired historical Create may return
409 after Install; inspect retained signed evidence rather than assuming the
original Create failed. Do not copy host stores to another path to test recovery.

Local Create/Install carry signed packages, so their exact POST endpoints use
the bounded lifecycle-envelope size limit rather than the ordinary 1 MiB HTTP
body limit. At most two package uploads are admitted process-wide, from body
buffering through execution. Capacity exhaustion returns 503; preserve the
retained request and resume it rather than allocating a new operation identity.

## Backup and restore

Native backup after Agent bootstrap is currently unavailable. The commands below
apply only to supported archive generations; they are not a backup/recovery
procedure for a running Agent space. Do not substitute raw store copies or
directory relocation. See [current acceptance gates](agent-saga-status.md).

Stop the daemon before backup:

```bash
vosx space down team
vosx space backup team /var/backups/vos/team-2026-09-10
vosx space restore /var/backups/vos/team-2026-09-10 \
  --node-key /secure/team-node.key
```

Node identity secrets are excluded from the archive and must be retained
separately. Restore verifies the manifest and archived identity before
publication. `--replace` preserves an existing destination under a reported
sibling name; it never deletes it. The current format refuses unsupported live
Agent/service generations rather than copying their raw stores.

## Node-local adapters

Persistent listen addresses, built-in HTTP/SSH ingress, and native extensions
are configured in `<space-data>/local.toml`. `space caps` reports the effective
extension relay ceilings stored in the running endpoint. Enabled ingress does
not grant anonymous access. Local managed invocation uses the authenticated
operator workflow above, not a generic text-command dispatcher.

## Verification

Run the serial clean-break gate before handing off a branch:

```bash
just clean-break-check
```

It runs the clean bootstrap/production-owner/supervisor-adapter suites, CLI
tests, the explicit-feature `agent-recovery-check` (Private host/store/runtime
and portable recovery), and a static negative check proving that retired executables, paths,
commands, flags, and operational documentation have not returned.

## Release artifacts

```bash
just package-production-release
vosx release verify target/production-release
```

The version-2 release directory contains exactly `standard-runtime.pvm`,
`system-authority.vos`, `system-catalog.vos`, and `manifest.json` embedded by
the checked `vosx` binary. The actor files are complete, non-authoritative
package templates; new spaces re-sign them with their own root. Their manifest
program IDs identify the enclosed PVM, while file digests bind the entire signed
package. Bundling accepts no external program path. Verification rejects the
previous release generation, symlinks, special files, unexpected entries,
digest or program-identity mismatches, and any artifact that differs from the
binary's protocol pins.

The `package-production-release` prerequisites reproduce the runtime and both
system packages with `scripts/build-agent-release-artifacts.sh`, using the
immutable source and builder revisions recorded in the provenance manifest.
Build evidence is retained under `target/agent-release-reproduction/` (not
`/tmp`); failures never overwrite committed pins. Direct `vosx release bundle
--out FRESH_DIRECTORY` and `release verify` check the embedded bytes but do not
replace those source-reproduction or deployment gates.

Before distribution, run the workspace checks, Clippy, formatting, docs,
examples, all feature combinations, standard-program conformance and parity,
hostcall allowlist inspection, reproducibility tests under clean homes and
target directories, profile restart/failover/recovery suites, and physical
HTTP and SSH idempotency tests.
