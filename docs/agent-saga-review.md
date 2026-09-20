# Agent saga: r19 retirement review guide

[Current status](agent-saga-status.md) is authoritative for remaining work.
Review the r19 reference-only retirement checkpoint on `saga/agents`, with delta
`c8028394..saga/agents`. Do not confuse later implementation-only work with this
review boundary.
This is a scoped review checkpoint, not production or full-saga sign-off.

Keep two consolidated review groups:

1. Retirement contract and execution: SDK InvocationRetirement/AIRT and RuntimeWork
   ACK carry metadata and ordered references, never artifact preimages. Check
   commitment parity, strict bounds, authorization/signature verification, exact
   retained-result binding, expired/error retirement, retry, capacity and unchanged
   state on rejection. Clean result identity is now the SDK work commitment;
   restoration requires equality and legacy recovery/ACK entry points refuse clean
   results. Full SDK-to-execution correspondence is established before commit.
   Journal replay persists compact ACKs; custom-linear checks its own distinct
   retained layout. Review SDK runtime/wire, Standard runtime, driver, journal,
   Local/Shared adapters and the custom example.
2. Artifact and lifecycle integration: ABI r19 is a clean break, not a migration
   adapter. Runtime, system templates and builder pin source `3c5e44c7`.
   Verify independent reproduction, matched-generation packages, bundled Local
   recovery, and isolated CLI lifecycle evidence. No r18 store is qualified for
   r19. Check artifact pins and the exact binary/evidence indexed in current status.

Foundation commits `930a5450`, `76d37d4d`, `493a098c` and cutover
`3c5e44c7` are in the new delta. Earlier concurrency, recovery and restoration
work remains included but is not retroactively qualified across every profile.
The prior r18 review guide is preserved at `c8028394:docs/agent-saga-review.md`.

Performance evidence is deliberately bounded: ACK input falls from 1,092,566 to
9,220 bytes and gas from 276,552,182 to 20,952,819. Invoke gas rises 11.9%, leaving
a 15.9% gas reduction for the Invoke+ACK pair. Additional management calls and
whole-state costs remain. Instrumented debug-host timings are not release latency
or throughput; the ten-second startup target still fails.

Reviewer focus: do not accept structural authorization matching as signature
verification or as proof that work was accepted. Distinguish recovering an exact
retained acknowledgement from authorizing a new retirement. Confirm the
reference-only path cannot execute unseen work or trust missing preimages.
Inspect the preserved projection-retirement special case and custom-runtime
recovery separately from Standard-private checks.

Review read-only: no fixes, formatting, branch movement, commits or pushes.
Return severity, exact commit/file/line, violated invariant, concrete scenario,
reproduction evidence, suggested regression and overlap with later work.
Label hypotheses separately from demonstrated defects. Implementation owns fixes
on latest source to avoid conflicting reviewer edits.

Use isolated disk-backed builds and disposable stores. Preserve frozen clients
and release-specific evidence. The full saga still requires released Shared and
Private/Attested lifecycle/proofs, backup, complete CLI, touched-state scaling,
and quantitative production qualification; see the status document.
