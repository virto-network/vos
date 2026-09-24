# Agent saga: external Local recovery checkpoint

Review `saga/agents` (code checkpoint `86045e53`) relative to `90d6c37d`, the previous
fresh-root Create checkpoint. This is a scoped experimental lifecycle and
retry checkpoint, **not** a first-customer release or performance claim. The
[live status and release gates](agent-saga-status.md) remain authoritative.
Please return findings without editing `saga/agents`; implementation continues
on `wip/ch08-runtime-directory`.

## What changed

- A public HTTP lost-reply regression withholds Create's successful response
  after the daemon commits it. Exact CLI `--resume` returns the same signed ACK
  before and after daemon restart without republishing the physical generation.
- Debug Create phase tracing attributes Authority issuance, physical
  publication, Authority finalization, retirement and route reconciliation.
  It identifies synchronous control-path cost; it is not a release benchmark.
- An Authority-approved Local Install that the physical Standard guest rejects
  now retains its exact journal result, a distinct signed `MAF1` failure, and
  durable `CIS2` issuer evidence. The Authority actor finalizes that failure
  only for the pending Local Install. The internal controller verifies the
  physical rejection, finalizes and retires the lifecycle intent, and recovers
  the exact failure after restart without appending another head or installing
  the actor.
- The first-customer storage rule is explicit: external-state Local uses fresh
  dedicated roots; existing image Local deployments stay on the image path.
  Mixed-format migration is deferred. Public external Install remains disabled.

## Review questions

1. Does the public lost-Create-reply path ever trust the client file or saved
   ACK instead of independently verifying Authority finality and the original
   locked physical generation? Include retry after restart and expiry.
2. Can a rejected Install's signed failure be forged, substituted for an ACK,
   paired with a different receipt/request/generation, or accepted for a
   non-Local/non-Install lifecycle? Follow journal observation, issuer, CMI4,
   Authority actor and startup verification.
3. Across crash windows between physical rejection, issuer observation,
   Authority finality and retirement, can recovery strand the admission or
   publish a route to an uninstalled actor? Check exact retry and a subsequent
   valid management operation.
4. Does the production image path remain fail-closed for `MAF1`, and are fresh
   external roots still selected only by explicit configuration? Internal
   success does not authorize opening public external Install ingress.

## Evidence and boundaries

The public Create lost-response/restart subprocess regression passed with the
checked opt-in Authority and runtime candidates. The `MAF1` SDK/Authority
suite passed (249/1 ignored SDK, 76/2 ignored Authority actor), the 14 issuer
tests passed, and the physical two-successful-then-rejected Install fixture
passed after controller restart. The all-in-one physical fixture needs a
16-MiB test thread stack; a separate Create operation has passed at 2 MiB.
Default non-experimental `vos` check, formatting and diff checks passed.

Not covered: public external Install response loss or file-backed daemon
recovery for rejection; public external actor Invoke/ACK/Resume; near-ceiling
ACK file publication; final source-pinned release artifacts; three-node
Shared/Clerk; backup/restore, failover or load. The feature remains opt-in.
Debug Create spans remain multi-second, especially Authority finalization;
they are diagnostic and not a throughput claim.

Please report severity, commit/file/line, violated invariant, concrete
failure scenario and a regression. Distinguish demonstrated defects from
unmeasured design risks. Keep review scratch disk-backed and do not apply
fixes on `saga/agents`.
