# Agent saga: fresh-root external Local Create checkpoint

Review `saga/agents` relative to `0ffe19fc` (the previous reviewed
response-recovery checkpoint). This delta is a scoped experimental Local
integration checkpoint, **not** a first-customer release or production
performance claim. The [live status and release gates](agent-saga-status.md)
are authoritative. Please return findings without editing the review branch;
implementation continues on `wip/ch08-runtime-directory`.

## What changed

- A source-built opt-in Authority template and Standard state-runtime PVM are
  generated and physically probed separately from the frozen release blobs.
  `vosx` embeds them only when both explicit build paths match checked digests.
- A fresh `local.toml` `external-state` selection uses the candidate Authority
  identity and dedicated Local journal/lifecycle roots. Missing candidates or
  conflicting image roots fail before those external roots are opened. Image
  deployments keep their released Authority/runtime identity and image path.
- The distinct signed state-runtime package carries explicit 500,000-row and
  512-MiB logical-row ceilings per lane. LCQ2 Local Create is prepared,
  retained, submitted and verified without coercing it into image LCQ1.
  The production owner uses the existing authenticated lifecycle and publishes
  routes only after finality and reconciliation.
- The internal external Install handoff now handles sequential Install
  generations and restart, but **public Install remains disabled**: an
  Authority-approved, permanently guest-rejected Install can otherwise strand
  its retained intent.

## Review questions

1. Can build-time candidate paths, digest checks or root-dependent signing
   accidentally change an image deployment or admit a mismatched ABI? Check
   `vosx/build.rs`, `bundled.rs`, package admission and the candidate builder.
2. Does a changed node-local storage choice or a surviving old root ever select
   the wrong Authority target, create a mixed-format lifecycle request, or
   open a root before refusal? Check `local_config.rs`, startup, CLI target
   derivation and the LCQ1/LCQ2 store validation.
3. Across fresh Create, shutdown, restart and exact `--resume`, can a saved ACK
   or client file substitute for independent Authority and physical finality?
   Challenge pending/denial branches, response-loss windows, package or
   generation substitution, and route publication after authenticated finality.
4. In the internal sequential Install handoff, challenge retained sidecars,
   existing-owner locks, predecessor checks, guest rejection and retry after
   a partially published application. Do not treat its passing fixture as
   permission to open public Install ingress.

## Evidence and boundaries

The checked Authority and state-runtime candidate outputs were byte-identical
across separate builds/conversions. The state PVM passed a physical XSW2 Create
probe. The opt-in `vosx` binary created a fresh external Space and Local Agent
over HTTP, restarted, and returned the exact same signed ACK on `--resume`.
The default image-space startup smoke, image Create/Install regressions,
clean-store regressions, local-config tests and release-bundle reproduction
passed. One clean-store and two image Create tests needed loopback permission;
their sandbox failures were not source failures.

The debug-binary Create run took 21.46 seconds: 3.26 seconds before request
retention and 17.96 seconds waiting for a verified daemon response. Exact
post-restart retry took 4.26 seconds (0.16 + 3.84). These are diagnostic
timings, not latency qualification. Attribute the daemon's Authority,
execution, publication and route phases before optimizing or blaming the PVM.

Not covered: deliberate response loss during delivery, public external
Install/Invoke/ACK/Resume, near-ceiling ACK, final source-pinned release
artifacts, multi-node Shared/Clerk, backup/restore, failover or load. The
feature remains opt-in; no migration from image roots is in this release.

Please report severity, commit/file/line, violated invariant, concrete
failure scenario and a regression. Distinguish demonstrated defects from
unmeasured design risks. Keep review scratch disk-backed and do not apply fixes
on `saga/agents`.
