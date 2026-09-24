# Agent saga: block-runner preparation checkpoint

Review `41ec8779..4140c697` on `saga/agents` (plus this review-note
commit). This is a bounded performance and release-gate checkpoint, not the
first-customer release. The [live plan](agent-saga-status.md) is authoritative.
Please return findings without editing `saga/agents`; implementation resumes
on `wip/ch08-runtime-directory`.

## What changed

- The experimental block-fetch runner retains one prepared PVM program per
  executing thread, switching only on exact program bytes. Admission, gas,
  root verification, host calls and result validation still run on every
  invocation. The cache holds no result, state root, file descriptor or lock.
- A focused test switches between two physical programs and back, checking
  their distinct host-call counts. The non-ignored block-runner suite and the
  signed physical external-Local Clerk Create/Invoke/reopen fixture passed.
- Stale comments were corrected and the live plan now states the actual
  Shared gates: one-voter system bootstrap, no public ordinary Shared
  Create/Install, unavailable ordinary Shared finality, image-oriented Shared
  storage, and no fresh-key joiner handoff via portable restore.

## Review questions

1. Does `load_prepared` preserve the cold loader's execution semantics,
   including invalid programs, gas, input and host calls? Can exact-byte
   switching leak prepared state across unrelated Agents?
2. Is one cached prepared program per live worker an acceptable memory bound
   for the first release, given the 1.25-MiB program admission ceiling and
   worker count? The cache has no node-wide lock.
3. Do the Shared release-gate statements match the current production paths?
   In particular, do not treat V2 Raft committee-transition primitives or
   same-node portable backup as a complete three-node onboarding workflow.

## Evidence and limits

Before the cache, the same physical fixture took about 135–136 seconds in
debug and 101.83 seconds in an optimized `vos` test binary. After the cache,
it took 122.93 seconds in debug and 91.59 seconds optimized. Each post-change
figure and the optimized baseline are single runs; these are complete serial
fixture totals, not per-request latency or throughput measurements. The
optimized run used the canonical signed Clerk package and the same physical
Authority/runtime guests. Seven non-ignored block-runner tests, including the
focused exact-byte test, plus formatting and diff checks passed. Full outer-PVM
recovery, released `vosx` CLI and three-node Shared load were not rerun here.

The cache is a measured constant-factor improvement, not a capacity claim.
Shared external-state storage, common three-node system placement, ordinary
Shared Create/Install, public routing, retained growth, production credentials,
backup/restore and service load remain release gates. Please report severity,
file/line, violated invariant, concrete failure scenario and a regression;
distinguish demonstrated defects from design risks.
