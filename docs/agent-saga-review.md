# Agent saga: inventory checkpoint review guide

[Current status](agent-saga-status.md) is authoritative for evidence and remaining
work. Review `saga/agents`, with new delta `7bd66a7d..saga/agents`.
This is a scoped Local checkpoint, not production or full-saga sign-off.

Keep two consolidated review groups:

1. Immutable invocation resolution: source `eef8890a`, artifact integration
   `07c7d1b8`. Invoke/Resume retain a private resolution object bound to the
   original SDK work. Commit still authenticates the work and authorization and
   checks the complete current actor record. Review stale provenance, substituted
   preflight and bound/unbound equivalence; do not mistake structural matching
   for signature validation. Unbound callers retain full validation.
2. Authenticated inventory stream and integration: sources `525319d5`,
   `2ccfacb8`, artifacts `9fe6762e`, plus the checkpoint recovery regression.
   Review SDK authority/wire, the compiled system-authority endpoint, production
   inventory owner, query dispatch/retirement classification and package pins.
   The host replaces six small-inventory queries with one bounded stream, not
   with private-state decoding or a native fallback. The old production
   per-Agent replica/actor loaders are removed; other legitimately used
   standalone projection APIs remain.

## Invariants to challenge

- Signatures bind Authority, credential, nonce, cursor, limit and known-head hint.
  Fresh authentication precedes unchanged-head reuse. Credential rotation cannot
  reuse another credential's rows; revoked credentials cannot reveal inventory.
- Every page has one consistent head and complete credential claims. Private
  visibility applies to descriptor and child rows. Cursors advance strictly,
  including across filtered Agents; no row can be attributed to the wrong Agent.
- Limits cover 64 total rows, eight complex rows, and the 16 KiB wrapped reply.
  Descriptor reconstruction checks full roster counts/generations, actor capacity
  and ordering. No partial inventory is published and every failed refresh
  invalidates reuse.
- Invoke/ACK identity and durable pending recovery remain exact. Interrupted
  retirement may replay retained work, never authorize a different request.
  The compiled-Authority recovery test exercises pending Invoke, durable ACK
  with failed pending-record clear, reopen, competitor refusal and fresh successor.
- Program identities and digests agree across manifest, host pins and bundled
  artifacts. Runtime and both system templates reproduce from `2ccfacb8`;
  template builder remains pinned to `3c5e44c7`. ABI remains r19.
  Use fresh test spaces; there is no qualified old-store migration.

## Evidence and limits

See current status for exact frozen CLI/test-client hashes and log paths.
Source hostile-page tests, the 527-query scripted journal rotation campaign,
compiled endpoint/outer-runtime tests and fresh CLI lifecycle have distinct
scopes. None alone establishes all-profile recovery or production capacity.

The stream reduces invocation count, not whole-state transport/restoration,
publication or signature cost. Unchanged-head authentication still costs one
query. Growing compiled directories, idle-Agent scaling, released-node tail
latency and thousands-active-user throughput remain unqualified.
The ten-second readiness target fails for this fixed checkpoint's campaign.
Later implementation-only qualification is recorded separately in current status;
do not apply its results retroactively to this review boundary.

Earlier r19 retirement evidence and review instructions remain at
`7bd66a7d:docs/agent-saga-review.md`; the prior implementation qualification
journal remains at `9fe6762e:docs/agent-saga-status.md`. Do not treat historical
pending-work statements as the current backlog.

Review read-only: no fixes, formatting, branch movement, commits or pushes.
Return severity, exact commit/file/line, violated invariant, concrete scenario,
reproduction evidence, suggested regression and overlap with later work.
Label hypotheses separately from demonstrated defects. Implementation applies
findings on latest source to avoid conflicting reviewer edits.

Use isolated disk-backed builds and disposable stores. Preserve frozen clients
and release-specific evidence. The complete saga still requires all gates in
current status; this checkpoint does not narrow the goal.
