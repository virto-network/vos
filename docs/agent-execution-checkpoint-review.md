# Execution checkpoint evidence

This is source-review evidence, not deployment or architectural sign-off.
Use [current status](agent-saga-status.md) for the authoritative plan.

## Fixed review checkpoints

- `92ce97f4`: independent-Agent supervisor dispatch, Local exclusive execution
  leases and per-Agent inline routes; targeted actor lookup and reused directory
  audits. Four independent 100 ms reviewer jobs completed in 100–101 ms rather
  than roughly 400 ms. This is a coordination experiment, not a throughput test.
- `817e528c`: inline retirement drains operations and drops backend ownership
  even while closed cloned handles survive. Physical root-reopen and lifetime
  tests pass; error/panic paths remain fail-closed.
- `9acb7ef4`: one bounded refresh worker separates reconciliation from serving.
  Old/proposed lanes remain behind generation barriers; unrelated dispatch
  continues. Stale detach, overload, failure and shutdown tests pass.
- `1b977731`: targeted catalog validation runs outside the shared registry
  lock under an exclusive Agent lease. Held-scan independence, validation-error
  cleanup and directory replacement tests pass.

The two original reports are retained under
`target/agent-review-e20cbb76.PswdnZ/` and
`target/agent-review-92ce97f4.kUhgwO/` in the repository root.
Their findings are checkpoint-specific, not automatically current failures.

## Evidence and scope

Logs under `.worktrees/ch08-c2-native/target/task-tmp/` include
`inline-retirement-final.log`, `refresh-isolation-final.log`,
`refresh-isolation-repeat.log`, `catalog-isolation-local-final.log`,
`catalog-isolation-supervisor.log` and `catalog-isolation-vosx-check.log`.

At `1b977731`, the candidate Local suite had 20 passes and one known
substituted-history recovery failure. That failure is fixed in the newer
`a1ebce16` source; see [recovery evidence](agent-recovery-contract.md).
Do not keep treating it as an unfixed source defect, or infer that its source
fix already qualifies the older bundled artifact.

Limits recorded at `1b977731`: synchronous node inventory; Attach/retirement callbacks;
explicit namespace/lifecycle audits under the registry lock; whole-state VM
transport/publication; unqualified memory/descriptor budgets; conservative
whole-host failure on uncertain Local execution; broader Shared/Private,
backup, capacity and release gates. Targeted responses do not imply
touched-state execution cost.

Do not use that historical list as the current backlog. Implementation commit
`caeeac18` moves node inventory/lifecycle work to a bounded control worker;
it is not yet in review checkpoint `16adf95e`. This isolates scheduling but
does not reduce physical inventory execution costs. See
[current status](agent-saga-status.md) for current evidence and remaining gates.

The longer chronological handoff remains at
`a1ebce16:docs/agent-execution-checkpoint-review.md`.
