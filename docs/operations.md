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

There are currently no public Agent creation, actor lifecycle, invocation,
membership, credential, or recovery verbs. An unknown top-level word is a
usage error; it is never treated as a dynamic actor name. This keeps the
intermediate cutover fail-closed while system authority/catalog bootstrap is
completed.

## Backup and restore

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
extension relay ceilings stored in the running endpoint. The cutover CLI does
not provision ingress credentials or dispatch actor methods.

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
