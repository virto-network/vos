# Next review checkpoint: execution isolation and targeted access

Current review handoff: [execution checkpoint](agent-execution-checkpoint-review.md).
The chronological notes below include superseded intermediate states. Local
production routing now uses per-Agent inline adapters and exclusive driver
leases; targeted lookup and pinned-slot checkout are implemented. Full node
maintenance isolation, runtime/bundle compatibility and generic-runtime history
validation remain open. This is not release qualification.

The review branch `saga/agents` now carries implementation checkpoint `92ce97f4`.
The previous review baseline is `e20cbb76`. Implementation base29a745c2 preserves
all previous Shared/row-state follow-up; it is explicitly unqualified, not a
release. Implement here, then provide two consolidated review groups.

## Group 1: ownership and correctness

- Continuation terminal capacity and interruption/restart regressions.
- Accurate registry-only backup documentation; no unsafe allowlist expansion.
- Bounded supervisor admission separate from execution; per-Agent ownership
  through the Local adapter, not just concurrent supervisor dispatch.
- Same-Agent ordering, generation/upgrade/detach races, fairness, retirement
  scheduling, overload and shutdown must have explicit tests.

## Group 2: targeted access and maintenance

- One verified directory enumeration per audit; generation-bound targeted
  actor lookup without repeated scans of unrelated actors.
- Per-Agent owned handles; full namespace audits at explicit lifecycle/recovery
  boundaries rather than on every targeted invocation.
- Bounded reconciliation outside serving queues, atomic revision-consistent
  publication and explicit freshness/revocation behavior.
- Measure runtime calls, traversals, bytes, queue wait and service time before
  and after; retain full authentication, commitments and crash semantics.

## Evidence and remaining work — 2026-09-20

Initial terminal-slot change permits64 resume exchanges plus one ACK, validates
the extra entry's action and preserves the old exact predecessor checks. A65th
resume is refused with an explicit non-recoverable-by-unchanged-retry message;
no history is discarded. The general durable64MiB bound remains unchanged.
Before dispatch, the client now reserves maximum response bytes plus the exact
terminal request and maximum terminal reply, including hex/JSON overhead.
Arithmetic overflow and one-byte-over-budget tests fail closed. Histories
already too large for this reservation are preserved but not dispatched.
This is not a chunked-history implementation; arbitrary long-job support is
not claimed. Unsupported limits explicitly say unchanged retry cannot advance.

All6 invocation_progress tests pass,0 failed/ignored, in5.70s. New tests cover
63/64 resumes followed by pending-ACK reopen and completed-ACK reopen, plus
refusal to use the terminal slot for another resume. Existing loopback exact
retry coverage passes. The new boundary test drives durable publication/codecs,
not an actual actor through64 execution slices; a full boundary transport/fault
test remains useful. Log under shared target/task-tmp:
`continuation-review-fix-final.log`. git diff --check passes.

The first build saw stale frozen-worktree dependency artifacts in the shared
target; targeted package cleaning and rebuild resolved the missing API errors.
Cleanup removed81.2GiB generated artifacts for vos, SDK, PVM and compiler;
preserved release/client evidence was not removed. A subsequent test compile
required a mutable store binding, then the complete selected group passed.

The full-history transport regression now completes64 resumes, retains the65th
ACK request, receives503, reopens and retries the byte-identical ACK, then
reopens terminal state without contacting transport. All8 selected tests pass
in8.58s with loopback access (`continuation-review-transport.log`). No physical
actor64-slice qualification or arbitrary-length history claim is implied.

The actual supervisor experiment rebuilt against latest source repeats three
times: one supervisor/four independent routes, peak1 and400ms; four supervisors,
peak4 and100/101ms. This isolates100ms synthetic route work, not PVM throughput.
Supervisor tracing now separates admitted queue wait and service microseconds.

Local physical audits now borrow one opaque physically verified directory from
the immutable driver. Per-actor material resolution uses this view, retaining
all artifact/package checks; the caller cannot supply replacement records or
mutate the driver while borrowing it. Both exact audit and one-ACK-ahead audit
use the view. Targeted normal invocation still enumerates the directory: no
persistent generation cache or request-path scaling claim yet.

Qualification exposed the known source/bundle mismatch: default Local-host
suite9pass/5fail at creation (InvalidRuntime), before the modified audit path.
Explicit preserved row-runtime ELF selection passes13 and fails1. The failure
is substituted management-history reopen: driver.open_sdk only cross-checks
standard private history for STANDARD_RUNTIME_PROGRAM_ID; the candidate has a
different ID and takes the generic-runtime path. Do not hide this failure or
claim candidate tests qualify the bundled release. It is further evidence for
the planned runtime-independent contract work. Logs: local-directory-review.log
and local-directory-review-candidate.log. New enumeration-count assertions are
now pass separately against that candidate: one physical lifecycle regression,
4.96s, including one directory execution and no additional directory execution
for three material lookups; exact material equality with the old path and
missing-actor refusal. Log: local-directory-review-counts.log. This is a
single-actor regression, not the full32/256/1024-actor scaling campaign.

The12 supervisor baseline tests also pass after adding queue/service tracing
(supervisor-baseline-review.log). Serialization is not fixed by instrumentation.

## Execution ownership decisions to implement next

### In-progress supervisor implementation

The supervisor now owns a bounded per-Agent lane scheduler and a fixed worker
pool. Dispatch no longer waits on the coordinator thread. A route adapter is
moved exclusively to a worker and returned on completion; each attachment is
still exclusive, while separate attachments for independent Agents overlap.
Lane ordering spans actors and attachments sharing `(SpaceId, AgentId)`.
Unique completion tickets prevent stale completions from releasing newer jobs.
Queue capacity counts both the command queue and waiting lane jobs. Worker
completion wakes the coordinator without a polling interval. Pending detach/
refresh barriers wait for their Agent lanes and stop new admission for those
lanes; unrelated dispatches remain runnable. Shutdown rejects queued work,
joins the execution pool and then retires adapters. No thread-per-request model.

The first async regression stalled in the queue-capacity test because draining
the command channel hid queued lane jobs. The exact live test session was
interrupted after diagnosis; global queued admission was restored. All47
selected supervisor/adapter tests then passed (0.05s with event-driven wake),
including independent-route overlap before either release, same-Agent ordering
across attachments, waiting-detach isolation, bounds, stale generations, panic,
unpublication and worker join. Log: supervisor-async-wake.log under shared
target/task-tmp. This is not a physical Local concurrency qualification.

A further FIFO guard prevents a blocked attachment's first job from being
overtaken by another attachment's job in the same Agent lane. Its final rerun
passes48 tests,0 failures/ignored,in0.06s (supervisor-async-fifo.log).
The Local backend still holds its host-wide
mutex and one adapter covers multiple Agents; that ownership split remains
required. Reconciliation/retirement work itself can still block the coordinator;
full maintenance isolation and fairness/retirement stress coverage remain open.

- Ordering key is `(SpaceId, AgentId)`, not actor route or attachment ID.
  Multiple actors/attachments for one Agent cannot evade its execution order.
- Global admission remains bounded by request count and owned payload bytes;
  execution needs a bounded worker pool and fair ready-Agent scheduling, not
  one thread per request or unbounded per-Agent queues.
- Jobs own their admission reservation through completion/cancellation. A
  disconnected client cannot release capacity while its job is still executing.
- Route snapshots are generation-bound. Lifecycle admission closes the old
  generation; define which already-admitted jobs drain and reject the rest.
  Refresh/upgrade publishes only after that Agent's lifecycle barrier completes.
  Waiting for one barrier must not block unrelated Agent admission or execution.
- Detach hides routes first, then drains/retires the affected execution owner.
  Shutdown rejects new work, resolves queued callers and joins all workers.
  Worker panic invalidates the affected routes; no stranded reservations.
- LocalAgentHost keeps namespace/lifecycle ownership, but per-Agent drivers
  need independent leased ownership. Do not release the global host lock around
  raw driver pointers or bypass validation. Registry/lifecycle and request locks
  need a documented order, with generation checks before executing accepted work.
- Full root auditing moves only after durable root/Agent ownership is explicit;
  tests for replaced paths, missing artifacts and unowned directory entries must
  be classified as request-time versus lifecycle/recovery invariants, not removed.

Next acceptance tests must exercise independent physical Local Agents through
one production supervisor, same-Agent multi-actor order, upgrade/detach while
busy, panics, cancelled callers, overload and acknowledgement scheduling.

Next: define lane ownership and lifecycle barriers before changing concurrency.
Do not infer performance improvement from the continuation fix or source-derived
directory counts. No new runtime artifacts are qualified.

The full saga also retains later acceptance requirements: runtime-independent
production validation with a different-layout custom runtime, touched-state
cost scaling, released Shared lifecycle/recovery, native portable backup,
general CLI/multi-profile lifecycle and production release/capacity gates.
