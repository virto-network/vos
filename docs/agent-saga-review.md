# Reviewing the Agent architecture saga

Current Ch08 WIP warning: `wip/ch08-runtime-directory` has independently
reproduced r16 bundles and passing fresh-space startup/restart ingress checks,
but ordinary-agent finality, cross-runtime actor lifecycle, and full release gates
remain open. This is not a master-ready branch.
See the current closeout plan below; later checkpoint sections retain historical
results, including failures that have since been fixed.

## Current closeout plan

Implementation is in `.worktrees/ch08-runtime-directory` on
`wip/ch08-runtime-directory`, not yet in the root `saga/agents` checkout.
Use only an isolated, disposable environment for bootstrap/ingress testing.
Fresh-space first start and restart with bundled system actors and HTTP/SSH
have passed; ordinary-agent creation is not yet a usable production path.
Those ingress checks predate the new AJC4 checkpoint and AGI3 Local image
formats. A newly built CLI needs a fresh disposable data directory and another
smoke run; AJC3 checkpoints and AGIM/AGI2 images are deliberately rejected, with no
in-place migration provided.

The integrated library run at `37d6a5720e7e45e4a19850a16a531e6cb316e299`
completed: **1,663 passed, zero failed, one filtered**, in 1,771.43 seconds.
It used `pvm,private-agent-store`, serial tests and socket access. Evidence:
`.worktrees/ch08-c2-native/target/task-tmp/r16-integrated-library.log` (path
relative to the main checkout). The filtered large inventory test still needs
a final-source run. Later SDK and host persistence/recovery edits have separate
passing targeted checks documented below, not a completed full-library rerun
on the current source.

Keep the remaining work in three scoped Chapter 08 batches, without adding
review endpoints for individual fixes:

1. **C1 — recovery:** preserve the integrated portable-recovery fixes. Host-owned
   management evidence now survives checkpoint/GC/reopen and feeds the Shared
   projection comparator. Physical Shared certified snapshot/compaction and
   substituted-evidence reopen checks now pass, as do portable evidence
   preservation and the post-snapshot one-ack-lag projection checks described
   below. Production Local opaque-runtime management Create/reopen now uses
   public metadata and durable history. Scripted physical-PVM actor installation,
   invocation/resume/reopen and lane-transition checks now pass. Complete the
   remaining positive-ack retirement and migrated invocation/retry checks.
   Target-runtime directory compatibility is now checked before Local cutover;
   the scripted host-ABI tests do not prove arbitrary guest execution semantics.
   Neither a private-state decoder nor a volatile cache is a runtime-independent
   proof.
2. **C2 — native lifecycle:** connect ordinary-Agent provisioning to the native
   owner, not just its existing invocation route workers. Startup currently
   attaches the system Agent only; the route worker exposes no Create/Install
   management command. Drive authenticated authorization, durable issuance,
   physical application, acknowledgement and route publication as one
   restartable workflow. Replace the deliberately unavailable ordinary-Agent
   finality adapter with authenticated live system-Agent decision publication
   and independent replay verification, including reopen. A self-consistent
   provision or permissive verifier is not sufficient. Prove ordinary-agent
   creation, actor installation, invocation and restart from the actual native
   entry point, not a manually prepared library host.
3. **C3 — release:** after those implementation changes, freeze source, rebuild
   and independently reproduce artifacts, run the final feature, physical,
   inventory, docs/examples and release checks, and repeat the fresh-space
   smoke. Fold internal checkpoints into the scoped review batches and only
   then advance the integration/review branches toward master.

The broad regression result closes the fourteen previously observed library
failures. It does not close either implementation gap or certify master
readiness. Avoid another full build/artifact repin before those changes are
ready, and keep temporary build data on disk under `target`, not RAM-backed
`/tmp`.

The nested system actor libraries also pass on `ae66a058`: Authority **58/58**
and Catalog **10/10**, with no ignored or filtered tests. Evidence beside the
library log: `r16-authority-actor-final.log` and `r16-catalog-actor-final.log`.
The commands used locked, offline dependencies and disk-backed scratch space.
The root workspace does not execute these nested workspaces' unit tests, so
`agent-system-actors-check` now explicitly includes both in `clean-break-check`.
The recipe expansion was checked; its two underlying test commands passed
individually. The full composite release recipe has not been rerun. SDK
`cargo check --no-default-features` also passes after the lint-only edits
(`r16-sdk-no-std-final.log`).

The completed Agent architecture chapters are integrated on `saga/agents`. They are reviewed
as a stack of larger, single-theme chapters; `master` receives only the
completed clean cutover after the release gate passes.

Every range below is base-exclusive and head-inclusive. Review the chapters
in number order, targeting each numbered review branch at the preceding
chapter. The SHA ranges remain canonical even when a local review branch has
not yet been published.

For one chapter:

```bash
git log --reverse --oneline <base>..<head>
git diff --stat <base>..<head>
git diff --check <base>..<head>
git diff <base>..<head>
```

Private modules are not enabled by default. Every Private gate below
therefore names `--features private-agent-store` explicitly. System actors
and custom runtime examples are nested workspaces and are addressed through
their manifests.

## Review chapters

| Chapter | Local review branch | Range | Scope |
| ---: | --- | --- | --- |
| 01 | `review/agent-saga-01-runtime-pvm-foundation` | `eb81aa37..f114edfe` | 30 commits; 382 files; `+41832/-4393`. Standard-PVM Agent runtime model, typed packages, lifecycle and actor execution, authority receipts, PVM v0.8/conformance, Raft redirect boundary, and source-derived production pins. |
| 02 | `review/agent-saga-02-durable-system-agent` | `f114edfe..1bd25329` | 42 commits; 107 files; `+113972/-3181`. Authenticated journals and lanes, continuation proofs, invocation history, system authority/catalog, exact replay/finality, restartable publication, clean host boundary, and corrected pin. |
| 03 | `review/agent-saga-03-sdk-private-physical-host` | `1bd25329..1cd01638` | 73 commits; 140 files; `+77931/-6120`. Portable SDK and VOS3 packages, scheduling/continuations and storage proofs, encrypted Private storage/sync/backup, Shared Raft apply, physical VOS3/Private hosts, ingress, identity stores, and Agent network protocol. |
| 04 | `review/agent-saga-04-authority-operation-recovery` | `1cd01638..5945ee1d` | 42 commits; 78 files; `+59157/-3135`. System authority/catalog actors, offline Private recovery, Agent-only authoring and custom-runtime kit, AOC/AOP/AOI issuance and application, PCA, enrollment, catalog compaction, and mandatory Private-sync authority evidence. |
| 05 | `review/agent-saga-05-release-private-closure` | `5945ee1d..b667bfdb` | 26 commits; 60 files; `+16527/-12532`. Host identity and backup confidentiality, release/docs/examples, all Private controls, fail-closed authority-state publication, system-Agent bootstrap, recovery-key/PRA1 binding, exact PSE2 evidence, and staged PVRP3 publication/restart. |
| 06 | `review/agent-saga-06-private-runtime-bridge` | `b667bfdb..2c98b8c1` | 41 commits; 45 files; `+33749/-5068`. r12/r13 management authorization and resource policy, terminal Private capabilities, canonical runtime evidence and lineage, physical lifecycle/storage/sync application, authenticated import provenance, and crash-safe replica establishment from encrypted archives. |

These six ranges cover all 254 source commits through `2c98b8c1` exactly once.
Chapter 01 is intentionally generated-heavy: review its source and pin recipe,
then verify the derived vectors/artifact by identity rather than line-reviewing
generated bytes. Chapter 02 remains separate because it is already the largest
source chapter; combining it would make the review materially harder. Chapters
03 through 06 each retain a coherent physical-host, authority, or hardening
model while reducing endpoint overhead.

## Chapter invariants and gates

### 01 — Runtime and PVM foundation

Typed packages are the only admission path, invocation replay is exact, lane
separation is enforced, and lifecycle authority precedes mutation. ISA, gas,
and control-flow semantics match the official vectors; leader handoff
preserves the exact invocation; generated identities are source-derived.

```bash
cargo test -p vos --lib agent -- --test-threads=1
cargo test -p vos-pvm --lib
cargo test -p vosx
just test-pvm-vectors
just test-pvm-proof-fast
just verify-agent-runtime-release
```

### 02 — Durable system Agent

Append precedes publication, replay is idempotent, authority retirement cannot
outrun durable evidence, and catalog publication resumes from retained intent.

```bash
cargo test -p vos --lib agent::journal -- --test-threads=1
cargo test -p vos --lib agent::catalog_finality -- --test-threads=1
cargo test -p vos --lib agent::system_authority -- --test-threads=1
cargo test -p clerk-ledger --lib
just verify-agent-runtime-release
```

### 03 — SDK, Private storage, and physical hosts

Wire/package identities are canonical; transitions and storage descriptors are
signed; Private state stays ciphertext-only; continuation proofs bind exact
inner state; obsolete package generations fail closed. No unauthenticated
restore can publish; feature-gated tests reach the real Private host;
management retries are exact; snapshot retirement follows durable storage;
Node identity and network routes use full bindings.

```bash
cargo test -p vos-agent-sdk -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_host -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private -- --test-threads=1
cargo test -p vos --lib agent::shared -- --test-threads=1
cargo test -p vos --lib agent::clean -- --test-threads=1
cargo test -p vos --test agent_runtime_pvm -- --test-threads=1
just check-no-std
just test-pvm-proof-fast
just verify-agent-runtime-release
```

### 04 — Authority operations and recovery

The actor selects authority; both recovery halves are required; history and
key lineage are exact; acknowledgements use reserved invocations; transport
identities are full-ID bound. Authoring exposes no service-era route, weak
authority keys fail, and custom runtimes obey the same package, ABI, and
scheduling contract. Authorization, issuance, and application use distinct
Linear invocations; AOI proves issuance rather than application; PCA binds the
exact applied control; actors consume only retained sources; enrollment and
PSE values cannot alias.

```bash
cargo test -p vos-agent-sdk --lib authority_operation -- --test-threads=1
cargo test --manifest-path actors/system-authority/Cargo.toml -- --test-threads=1
cargo test --manifest-path actors/system-catalog/Cargo.toml -- --test-threads=1
cargo test -p vos --lib agent::authority_operation -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_control_application_coordinator -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_sync -- --test-threads=1
cargo test -p vos-raft --lib
cargo test -p vosx
cargo test --manifest-path examples/agent-runtimes/custom-linear/Cargo.toml
just test-examples
```

### 05 — Release and Private recovery closure

Fresh and joined identity material is protected and bounded; backups contain
no plaintext; retired Service surfaces cannot re-enter the release; old proof
wires fail closed. Unpublished or unapplied controls never advance authority
state; old state generations fail; recovery binding is immutable; PRA1, PCTL,
and authority head are transitively exact; two valid PRA1 values for one PCTL
cannot mix.

```bash
cargo test -p vosx
cargo test -p vos-agent-sdk -- --test-threads=1
cargo test -p vos-agent-sdk --lib authority_operation -- --test-threads=1
cargo test --manifest-path actors/system-authority/Cargo.toml -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_control_application_coordinator -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_sync -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_store -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_host -- --test-threads=1
just test-examples
just package-production-release
rg -n '\b(JAM|JAR|Gray Paper|service[-_ ]runtime|Service)\b' --glob '!pvm/**' --glob '!target/**'
git diff --check
```

Any result from the terminology search requires an explicit platform or
migration-history allowlist entry; an empty exit status alone is not the gate.

### 06 — Management policy and the Private runtime bridge

Management admission is authorized against compact, resource-bounded plans;
denied capabilities retire without mutation; Private controls are applied only
with exact authority and runtime evidence. Store, runtime, lineage, and sync
commitments remain transitively bound across restart and object growth. A new
replica is published only after an authenticated encrypted archive is replayed
through a crash-safe plan whose exact retry and completion receipt bind the
origin, final store, and final runtime lineage.

```bash
cargo test -p vos-agent-sdk -- --test-threads=1
cargo test --manifest-path actors/system-authority/Cargo.toml -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_control_application_coordinator -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_runtime -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_store -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_sync -- --test-threads=1
cargo test -p vos --lib --features private-agent-store agent::private_host -- --test-threads=1
cargo test -p vos --lib --features private-agent-store replica_establishment -- --test-threads=1
cargo test -p vos --test agent_runtime_pvm -- --test-threads=1
cargo check -p vos --features private-agent-store --all-targets
just test-examples
just verify-agent-runtime-release
just build-agent-runtime-release
cargo fmt --all -- --check
git diff --check
```

## History and future chapters

Keep security fixes, protocol-generation bumps, and source-to-artifact repins
as visible commits inside their chapter. Mechanical fixups may be folded only
when their parent change already carries the complete review intent. Never
hide `0195696a`, `fa7a474a`, `e507b298`, `98e4bbc7`, or `87329648`, and never
hide a generated repin in a source commit.

The remaining review endpoints are intentionally limited to two larger,
scoped chapters:

1. Chapter 07: proof material, scheduling and custom runtime, supervisor and
   system projection, and ingress closure.
2. Chapter 08: backup/recovery closure, legacy deletion, serial reproducible
   artifacts, final docs/examples, and the production release gate.

Later work should extend one of those chapters when it completes the same
invariant; it should not create another reviewer endpoint. Keep internal
security fixes, protocol-generation bumps, and repins bisectable. Advance a
review branch only after its base and head are immutable, all named tests run
with a nonzero count, `git diff --check` is clean, and generated artifacts are
absent or isolated in their own reproducibility-reviewed commit.

### Chapter 08 first-start acceptance

The new-space UX belongs to the native startup batch in Chapter 08. It does
not introduce another review endpoint. Before advancing `saga/agents`, verify:

1. `space new` prepares the root-signed bundled runtime and system actor
   artifacts and writes `local.toml` with HTTP and SSH ingress enabled.
   Default listeners are `127.0.0.1:8080` and `127.0.0.1:2222`; operators can
   edit the addresses for multiple spaces or remote access.
2. The first `space up` automatically finishes durable system Agent,
   Authority, and Catalog installation before reporting readiness and
   serving ingress. Cached packages alone do not satisfy this requirement.
3. A subsequent restart reopens the same installed system actors without
   duplicate installation or manual bootstrap commands. Verify this and
   actual HTTP/SSH listener availability on a host that permits sockets.

Creating an arbitrary application Agent is a later user action on the running
space, not a required action of `space new` or `space up`. This distinction
does not waive the saga's existing Agent lifecycle or finality release gates.

Current checkpoint (2026-09-11): configuration and bundled-package compatibility
tests pass. Bootstrap now supplies Authority program/schema/policy blobs in
addition to installation data. Its internal admission path samples the trusted
clock for a new invocation and recovers exact authorization from the journal
on retry. Both crash-before/after-every-phase tests pass with an advancing
clock and no duplicate slots. The bootstrap suite excluding inventory passes
12 tests. The 152 vosx tests, six gas/budget tests, and the physical Refine
proof/replay regression also pass. The large inventory/release gates have not
been rerun here.

The original real-artifact failure was `Replay(Executor(RuntimeExit { reason: OutOfGas,
pc: 440679 }))`, surfaced by the host as `CorruptResidue`, during Catalog
authorization with a 2-billion outer allowance. The bounded outer-runtime
allowance is now 5 billion plus the actor's unchanged maximum of 1 billion;
bootstrap explicitly selects the actor cap, not the outer allowance. Fresh
physical bootstrap reached durable `Complete`, with Authority and Catalog
installed and finalized. Measured authorization/finalization executions used
about 1.78–1.80 billion outer gas. A development build without interpreter
optimization timed out during production-route reconciliation, after system
bootstrap completed. Development/test profiles now optimize the interpreter
without disabling debug assertions or changing guest artifacts or gas accounting.
The optimized recovery attempt also exceeded the roughly 12-minute smoke
limit during production reconciliation. It continued executing authenticated
queries/replay but never reported `Space daemon ready`; the harness stopped
its disposable daemon and retained the data. HTTP/SSH probes and the subsequent
normal restart were therefore not reached. This is not deployment readiness.

The release batch must include the changed host/proof gas allowance in its
reproducibility and compatibility review. A separate custom-runtime host test
also failed in `supervisor_invocation_material` with `CorruptResidue`, before
the new admission check; its opaque-runtime material lookup needs triage.

Retained disposable evidence in the native worktree:

- `target/task-tmp/native-admission-restart.log`: underlying runtime failure.
- `target/native-admission-smoke`: interrupted space, config and blob cache.
- `target/task-tmp/bootstrap-focused-suite.log`: 12 passing bootstrap tests.
- `target/task-tmp/bootstrap-restart-clock-test.log`: advancing-clock crash tests.
- `target/task-tmp/native-ready-first.log`: completed real system bootstrap;
  unoptimized production reconciliation timed out.
- `target/task-tmp/native-ready-recovered.log`: optimized recovery also timed
  out during reconciliation; no listener-readiness claim.
- `target/task-tmp/physical-proof-budget-test.log`: passing physical proof test.

Follow-up profiling identified unoptimized host BLAKE2 SIMD hashing as the
dominant CPU cost (three-minute profile retained at
`target/task-tmp/native-reconcile.perf`). Development/test profiles now optimize
`blake2b_simd`, retaining debug assertions and every authenticated read/check.
Eight hash cross-check tests pass. Reconciliation now schedules its next run
from completion, preventing slow queries from making the next run immediately
overdue; all three production-owner tests pass, including that regression.

With hashing optimized, the retained smoke reached a concrete `InvalidProjection`
instead of timing out. Diagnostics confirmed equal descriptors but two physical
actors versus one projected actor. This is the protected Authority actor:
Authority intentionally excludes itself from managed inventory. The system
bootstrap owner now adds its exact root-certified Authority install before the
ordinary full physical audit. It never derives this exception from an inventory
response or from whatever bytes happen to be installed. Inventory attempts to
claim Authority are rejected; physical package/install mismatches remain fatal.
No actor schema, package template, guest artifact, or admission limit changed.
The new positive/hostile root-pinning test passes, and the bootstrap suite
excluding inventory now passes 13 tests. Diagnostic evidence is retained in
`target/task-tmp/native-ready-projection-recovered.log`.

A fresh `native-first-ready-smoke` space completed automatic system installation
and the full route audit. Its first listener bind failed because the existing
IPFS daemon owns HTTP port 8080. Only the disposable space's `local.toml` was
changed to HTTP `127.0.0.1:18080`; SSH remained `127.0.0.1:2222`, and the IPFS
daemon was left untouched. Reopening that space reached `Space daemon ready`,
returned HTTP 401 for an unauthenticated request, and completed an SSH host-key
handshake. Its clean shutdown succeeded. This is listener/authentication-boundary
evidence, not an authenticated arbitrary-Agent lifecycle test. Development
startup still takes minutes; release/performance gates remain outstanding.
Evidence: `target/task-tmp/native-ready-root-first.log` (port collision),
`target/task-tmp/native-ready-root-ports-recovered.log` and sibling HTTP/SSH
probe files (successful readiness). The same-space restart also reached readiness,
returned HTTP 401, completed SSH key exchange with the identical host key, and
shut down successfully. Its bootstrap phase remained `Complete`; the restart
reopened the installed actors through the normal authenticated bootstrap/audit
path. Evidence is in `target/task-tmp/native-ready-root-ports-restart.log` and
its sibling probe files. The bounded lifecycle script exited zero, and neither
test listener remained afterward. The successful reopen took about 3m45s and
the normal restart about 5m18s in the development build, so this is not a
performance sign-off. All 152 vosx tests also pass on this checkpoint.

Keep the ordinary-Agent finality adapter, custom-runtime material lookup,
portable recovery crash closure, reproducible artifacts, and final release gates
in the existing three Chapter 08 batches. These startup fixes alone do not make
the complete saga deploy-ready or authorize advancing `saga/agents`/`master`.

### Chapter 08 opaque-runtime directory correction (isolated r15 work)

The verified r14 native-startup checkpoint remains `f212f278` on
`saga/ch08-c2-native`. The follow-up source correction is isolated on
`wip/ch08-runtime-directory`; this is internal work in the existing startup
and artifact batches, not another review endpoint. Do not deploy this worktree
until its system templates and first-start/restart gates have also been updated.

The physical custom-runtime host regression reproduced `CorruptResidue` because
Shared invocation preparation decoded Standard-private state to recover install
lineage. Custom runtimes own an opaque state representation. ABI
`vos-agent-runtime-abi-260911-r15` therefore adds a required nonzero immutable
`install_request` commitment to `ActorDirectoryRecord`. Standard projects its
retained original install commitment (not the upgradeable entry), and the
custom Linear example returns its original install commitment. Shared preparation
now executes the canonical read-only directory query and admits the exact signed
package/artifact closure without decoding Standard-private state. Supervisor
checks require the directory and prepared material to agree on lineage.

The control-schema pin and ABI-dependent golden commitments were regenerated.
Directory tests independently check the field's byte position, reject missing
or zero lineage, and reject the previous ABI. Verification on this source:

- 160 SDK tests pass.
- 28 supervisor-adapter tests pass.
- The formerly failing physical opaque-runtime management/material/reopen test
  passes and checks the returned install commitment.
- Standard actor-upgrade coverage checks that the directory reports the new
  deployment but retains the original install lineage, without mutating state.
- The maintained custom Linear example passes 10 normal tests. Its r15 guest
  artifact has now been rebuilt, and the explicitly selected compiled
  scheduling/attestation test passes for Local and Shared profiles. Both native
  and physical directory checks assert the original immutable install lineage.
- A newly built Standard-runtime ELF passed the current CLI physical ABI probe;
  its PVM passed the explicit physical create/install/exact-retry/directory test.

The candidate is 935415 bytes, ProgramId
`6bcc6da44743202942746bfede64db263bbca704fc11c6d2e8f783bfa55c1df0`.
Its ELF reproduced byte-for-byte from an independent immutable export of
`78434a4f2d213badf1769f8ba4ec5d251d617a0d`; the runtime blob and digest pins
are now updated in this isolated worktree. All four active bundled-runtime
integration tests pass (one explicit candidate test remains ignored by default).
This is not yet a complete release-artifact reproduction gate. Evidence lives
under the native worktree's disk-backed
`target/task-tmp/r15-*.log`; the candidate is
`target/task-tmp/r15-agent-runtime-candidate.pvm`, and its ELF is under
`target/r15-guest/riscv64em-vos/release/agent_runtime.elf`.

The Authority and Catalog templates now also reproduce byte-for-byte (both
raw PVM and signed VOS3 envelope) across two independent source-export paths.
Their committed blobs and build-time digests are updated. Provenance, including
the immutable source and builder revisions, is in
`support/production-artifacts.toml`. The public template-signing seed is not an
operator credential: new spaces re-sign these templates with their own root.
The template builder never loads or creates an operator identity and rejects
existing output paths; all three focused safety tests pass.

To reproduce templates, build `vosx` from the pinned builder revision using
the pinned host toolchain, export the pinned template source revision into a
fresh disk-backed directory, and create an empty `.git` directory in that
export as the canonical source-root marker. Then run:

```sh
vosx release build-system-templates --source SOURCE_EXPORT --out FRESH_OUTPUT
```

The builder selects the dated guest toolchain; set `TMPDIR` to disk-backed
storage. Compare both output `.vos` files against the manifest digests. Current
two-export evidence is in `target/task-tmp/r15-system-templates-{first,second}`
and the corresponding logs under the native worktree. Host-tool independent
reproduction remains a separate outstanding gate; package reproduction alone
does not close it.

The release bundle now exports the actual Authority and Catalog VOS3 templates,
not the retired root-authority PVM and linked registry renamed as system actors.
Format `VOS-AGENT-RELEASE-2` binds full package bytes and enclosed program IDs;
verification admits the packages, checks canonical runtime compatibility, and
rejects the old format and legacy programs. The top-level release build recipes
now invoke the Agent-only reproduction script, which builds the pinned builder
from an immutable export and compares runtime and complete system-package
bytes against the committed pins. Full reproduction and production gates must
still pass before release.
The Agent-only script's full `all` run now passes, including an independently
rebuilt pinned host tool, exact Authority/Catalog package comparisons, the
runtime ELF digest, the physical runtime ABI conversion probe, runtime ProgramId,
and committed PVM comparison. Evidence is in the native worktree's
`target/task-tmp/r15-immutable-release-reproduction.log`; immutable exports are
retained in this worktree's `target/agent-release-reproduction/run.xi2Xa1`.
This closes the source/tool reproduction gate for these three artifacts, not
the other release, recovery, custom-runtime, or deployment gates.
Verification: all 156 active vosx tests pass (one explicit candidate test is
ignored by default), including 18 release tests. The rebuilt CLI successfully
bundled and verified `target/task-tmp/r15-release-v2-smoke` under the native
worktree. This proves the release-directory cutover, not deployment readiness.

Fresh r15 space `r15-startup` reached ready on its first startup at
2026-09-12 07:08:09 UTC (about 2m16s after network startup). Its automatically
created config enabled both ingress types; only the disposable HTTP port was
changed from occupied 8080 to 18080. HTTP returned 401 without credentials and
SSH returned its host key. The smoke script then cleanly stopped the daemon and
started the same space again. Restart reached ready at 07:12:15 UTC (about
4m03s), passed HTTP 401 and SSH handshake again, and retained the same SSH key.
The smoke script exited successfully and both test listeners were absent
afterward; the existing IPFS listeners were untouched. Evidence is under this
worktree's `target/r15-startup.oEbkfJ`. This is a development-build correctness
check, not a startup-performance sign-off or an ordinary-Agent creation test.

The static clean-break/retained CLI check also passes. Inspection caught a
separate gate omission: `agent::clean_bootstrap::tests::physical` requires the
`pvm` feature, so the default-feature inventory command selected zero tests.
The clean-break recipe now explicitly enables `pvm`; the corrected large
inventory rotation test must pass before that gate is considered closed.
With that feature enabled, all 13 other bootstrap tests pass, including
physical restart before and after every bootstrap phase and root-pinned
Authority auditing (`r15-bootstrap-physical-suite.log` under the native
worktree's disk-backed task logs). `cargo check -p vos-agent-sdk
--no-default-features` also passes (`r15-sdk-no-std.log`). The separate large
inventory test has now passed: one selected test, 514 authenticated queries,
and suffix rotation past 1,024 entries. Its log is
`r15-inventory-rotation-physical.log`; elapsed test time was 11334.20s (about
3h09m), not a performance sign-off. This run predates recovery integration,
so the final combined release gate still needs to run against its frozen head.

Next: finish the corrected inventory regression, then rerun physical,
proof, bootstrap, and real first-start/restart gates before integrating this
work into the native startup branch. The old r14 CLI correctly rejects the r15
candidate ABI; use the current CLI or its explicit
`compiled_runtime_candidate_uses_current_abi` candidate test with
`VOS_AGENT_RUNTIME_ELF` and `VOS_AGENT_RUNTIME_CANDIDATE_OUT`.
The integration test
`compiled_runtime_directory_reports_exact_install_lineage_after_restart` uses
`VOS_AGENT_RUNTIME_PVM` and must be run explicitly with `--ignored`.
The existing ordinary-Agent finality, recovery crash-closure, and release gates
remain open. The Standard-specific management-disposition lookup used only for
classifying projection lag also remains to be audited for opaque runtimes;
successful material lookup alone does not prove every custom-runtime lifecycle.

### Chapter 08 portable restore-marker verification

On the isolated `wip/ch08-c1-portable-recovery` worktree, the physical
`singleton_system_agent_portable_backup_is_authenticated_fresh_and_restartable`
test passes with `--features pvm`. It covers authenticated fresh-store restore,
occupied-destination rejection, restart, and process loss with either the
canonical restore marker or its staged `.next` file. Both marker forms must be
retired after recovery, and subsequent reopen preserves the fresh store identity
and journal position. Ten temporary portable-recovery diagnostic prints were
removed without changing error propagation or validation order.

Evidence: native worktree `target/task-tmp/c1-portable-marker-staged-verification.log`
(one explicitly selected test, passed). This does not establish every cross-store
crash boundary or the Private recovery gates, and this older recovery worktree
still needs integration with the r15 native/artifact work before final release.

The same physical test now also passes two cross-store interruption cases:
`heads.next` durably staged before promotion, and heads promoted while the
Raft ledger is still at genesis. The previously unused stop hook now reaches
the actual file-store publication boundary. Assertions prove staged heads
existed and differed from committed heads, reopen promotes exactly those bytes,
the stage disappears, and journal position/snapshot/store identity survive
another reopen. Evidence is `c1-portable-heads-stage-verification.log` in the
same disk-backed log directory. The broader Private host suite is separately
running with `pvm,private-agent-store`; it is not yet signed off.

Integration checkpoint: the recovery source is now combined with the r15
native/artifact work on the internal runtime-directory branch. The only merge
conflict was this additive handoff document; both evidence sections are retained.
All 63 Private host tests passed on the recovery checkpoint with
`--features pvm,private-agent-store` (`c1-private-host-store-suite.log`, 318s).
Combined-source verification is required before considering these results
release evidence for the integrated tree. No review endpoint or master advanced.
The recovery checkpoint additionally passes 40 Private store tests, 21 Private
runtime tests, and 6 tests selected by `portable`, all with the same explicit
features. Evidence logs are `c1-private-store-suite.log`,
`c1-private-runtime-suite.log`, and `c1-portable-suite.log`. The integrated
portable run is tracked separately in `integrated-portable-suite.log`.
That integrated run passes all 6 selected tests. The integrated Private host,
store, and runtime suites also pass 63, 40, and 21 tests respectively; evidence
is in `integrated-private-{host,store,runtime}-suite.log`. The serial release
gate now invokes `agent-recovery-check` with `pvm,private-agent-store` explicitly,
so disabled Private modules cannot silently bypass these suites.

Ordinary-genesis integration remains functional work, not just a release flag:
`clean_startup.rs` still installs `UnavailableAgentFinality`. The canonical
`system_authority.rs` decision/QC and historical-provision verification logic
exists, but `verify_historical_provision` currently has only test callers. A
production adapter must bind a provision to authenticated live-system replay,
including reopen and historical committee evidence; accepting a provision's
self-consistency or a standalone membership proof is not an adequate substitute.

Integrated Shared host verification: 15 of 16 tests passed in the sandbox;
the network convergence test failed waiting for a local listening address.
That exact test then passed with socket access (1.22s), without code changes.
Evidence: `integrated-shared-host-suite.log` and
`integrated-merge-pump-network.log`. The full final serial gate must run in a
socket-capable environment; the sandboxed suite's exit status was not green.

The broader integrated library run (socket-capable, `pvm,private-agent-store`,
serial, excluding only the separately verified inventory test) completed with
1649 passed and 14 failed in 1754.83s. Full evidence and failure details are in
`integrated-vos-library-suite.log`. This is a failed release gate. Failures span
issuer hostile-tag offsets, driver preflight, journal/shared-commit golden
identities, three Local SDK host physical tests, three wire tests, and two node
authorization tests. In particular, restore accepted mutated exact install
requirements and accepted-invocation provenance; do not dismiss these as golden
fixture churn or weaken the rejection assertions.

The issuer hostile-tag test was corrected to locate its operation byte after
the encoded managed target (instead of stale offset 96); its exact rerun passes
in `integrated-issuer-hostile-offset.log`. The other 13 failures remain open.
Workspace formatting validation passed before this test-only correction.

### Standard original-install validation correction (source ahead of bundle)

Do not deploy the current source worktree with its existing runtime blob. The
source now retains `CompactInstallActor` in Standard's `SCI2` private-state
installation table, replacing `SCAI`. Restore recomputes the original SDK
lineage commitment and requires exact contract/requirements plus stable
installation and reservation identities. This preserves original facts across
upgrades without retaining constructor bytes. The runtime must be rebuilt,
independently reproduced, repinned, and physically retested before release.

The exact install-state regression passes, including substitution of both
requirement copies without changing the signed lineage and rejection of the old
state marker. Upgrade/restart and historical-retry wire tests also pass. Fixture
builders which synthesize initial installations now update their original plan;
production rejection checks were not relaxed. The oversized nested-authority
test now encodes the current prefix and reaches the intended length bound.

The latest wire suite result is 65 passed, 1 failed in
`install-plan-wire-verified.log`: accepted-invocation provenance is still an open
failure. That remaining failure, the other full-library failures, finality, and
opaque-runtime projection recovery are not waived by the install-state fix.

### Integrated fixture corrections after the install-state checkpoint

The two node authorization failures were outdated registry stubs: enrollment
now requires a full authenticated peer roster row, not a prefix-only role byte.
The fixtures now answer the real `members` probe, reject unexpected probes, and
also assert that a different peer cannot borrow enrollment for sync or blobs.
Production authorization was not changed. All 120 node tests pass with socket
access (`integrated-node-roster-socket-suite.log`); the sandbox run passed 119
and failed only the listener-bind test (`integrated-node-roster-suite.log`).

The driver historical-receipt fixture now explicitly supplies the two empty
clean actor tables required for an initialized runtime. Its exact regression
passes (`integrated-driver-preflight-fixture.log`). These three corrections
leave eight of the original 14 full-library failures unaddressed: accepted
invocation provenance, three physical Local SDK host tests, and four journal /
shared-commit identity expectations. The full library gate has not been rerun.

The release path remains: fix the remaining runtime and ordinary-genesis /
opaque-runtime recovery blockers; rebuild and reproduce matching artifacts;
run fresh-space startup/restart and final release gates; then fold the work
into the three scoped review batches. The integrated WIP is not ready to land
on master or deploy with the currently bundled runtime. No branch was pushed
or merged to `saga/agents` or master by these fixture corrections.

### r16 accepted-invocation provenance correction (source only)

The remaining wire restore failure was a real binding gap: retained accepted
metadata contained availability references, but the signed work hash included
their preimages, so restore could not reconstruct and compare the signed work.
The SDK invocation commitment now encodes every invocation field and the exact
ordered BlobRefs, omitting only preimages. Admission still validates each blob's
bytes against its reference. Standard reconstructs that same commitment from
retained metadata before accepting either receipt or PublicPreflight bindings
for continuations and terminal results. It does not retain caller-sized blobs
or prohibit legitimate signed actor origins.

This changes the clean protocol to `vos-agent-runtime-abi-260912-r16`, with
control schema `0dd3107d1168fb23f2c1e6be24a57146b6d858908f4ffd57622716d2ff767c3e`.
All runtime/system packages and protocol golden expectations must be regenerated
and checked for this ABI; old bundles have not been repinned or rebuilt here.

The final wire suite passes all 66 tests in 20.83s (`r16-wire-final.log`),
including forged origin/message/gas/reference rejection, terminal-result origin
rejection, and a correctly signed actor origin surviving restore. The SDK adds
a regression showing reference binding and independent preimage validation.
SDK tests currently pass 153 and fail 8 ABI-dependent golden-hash tests
(`r16-sdk-final.log`); this remains a failed gate, not a waiver or a completed
golden refresh. SDK no-default-features and workspace formatting checks pass.
Seven of the original full-library failures remain unaddressed, in addition to
these r16 pin updates, ordinary-agent finality, opaque-runtime recovery, and
the final artifact/physical/release gates. No deployment readiness is claimed.

### r16 SDK golden refresh

All 161 SDK tests now pass (`r16-sdk-pins-final.log`). Fifteen expected digest
arrays were refreshed for the r16 wire generation across authority operations,
catalog, proof publication, runtime public I/O, and invocation context. The
canonical decoding, bounds, domain separation, and tampering assertions remain
unchanged. A separate Python hashlib calculation agrees with the r16 control
schema and runtime-public-I/O fixture digest. No bundle was rebuilt or repinned.

Current journal and shared-commit reruns reproduce the four earlier identity
expectation failures: journal 35 passed / 3 failed (`r16-journal-tests.log`),
shared commit 5 passed / 1 failed (`r16-shared-commit-tests.log`). Their observed
hashes match those from the earlier r15 run; they are not new r16 regressions.
They remain open pending accounting for their underlying encoding changes, as
do the three physical Local SDK host failures and architectural release gaps.

### Journal and Shared commit fixture closure

The four remaining identity-expectation failures are corrected without changing
production encoders. Their fixtures contain BlobRefs, whose hash domain changed
from `vos/blob/service` to `vos/blob` in `4e7d974d`; their old expected hashes
predate that change. Journal pins also predated later runtime binding changes.
Both current-domain and retired-domain comparison hashes were refreshed;
predecessor wire rejection and domain inequality assertions remain intact.

All 38 journal tests pass (`journal-pins-final.log`), and all 6 shared-commit
tests pass (`shared-commit-pins-final.log`), including signature and quorum
validation. Formatting and diff checks pass. The three physical Local SDK host
failures are now the only unaddressed failures from the original broad library
run, but that whole run has not been repeated. r16 artifact rebuild/reproduction,
ordinary-agent finality, opaque-runtime recovery, and all final release gates
remain required; passing these fixture suites is not deployment readiness.

### Initial r16 artifacts and exact-retry host correction

Runtime and system templates were built from immutable source
`42f3f3bf2362e5189f094a1e39c7288e7a26eea7`, with the builder from that same
revision and the pinned guest/host toolchains. Candidate evidence is under
`target/r16-release.ziYI98`; scratch data stayed on disk. The committed blob
candidates and production manifest now name r16. The runtime passed the physical
ABI probe with ProgramId
`1152a50e0117033569ddf9e7a71869adb8650184a63e3473a8ab88c72254cb00`.
This was one build, not independent reproduction or startup signoff. The normal
CLI binary was built before the new blobs were staged and must be rebuilt.

Host preflight incorrectly checked the current time for an exact retained
management retry, although the guest recovers that result before current-expiry
checks. Retained history now carries its recorded acceptance slot; only exact
retries authenticate against that slot. Other receipts still use the current
window, and signature/request/runtime checks remain unchanged. This host-only
change is newer than the guest artifact source. The exact preflight regression
passes (`r16-retry-preflight.log`).

With the r16 runtime candidate, Local SDK host tests pass 9 and fail 1
(`r16-local-host-tests.log`): both expired-retry failures are resolved, while
`physical_resume_boundary_replays_persisted_fifo_continuations` still returns
`Driver(InvalidRuntime)` at the first resume. This is the last unaddressed
failure from the earlier full-library run, not the last release requirement.
Artifact reproduction, current-source CLI rebuild/startup, finality, opaque
recovery, and the complete release gates remain open.

### Ordinary resume host validation corrected

The remaining Local host failure was in the host's Yielded-response validator:
ordinary `resume_sdk` supplies no optional original InvocationWork, but the
validator required it even though ResumeWork carries the exact availability
fields needed for this check. It now compares the yielded installation-data
marker and required references with the actual Invoke/Resume input. Identity,
mode, increasing ready sequence, guest validation, and Standard preflight /
persisted-continuation verification are retained. This is a host-only fix;
the r16 guest artifacts do not need another rebuild for it.

All 10 Local SDK host tests pass (`r16-local-host-resume-final.log`, 28.40s).
The resume regression now reopens the host between both yielded slices and
rejects tampered availability before continuing to the exact terminal reply.
All originally observed library failures have targeted passing reruns, but
the complete integrated library gate has not yet been rerun.

Independent artifact reproduction is running via
`scripts/build-agent-release-artifacts.sh all`; evidence log is
`r16-independent-reproduction.log`, with fresh exports under
`target/agent-release-reproduction/run.TYpSBz`. The active command session is
60130 at this checkpoint; poll it rather than launching another reproduction.
Its completion is not yet claimed. Finality, opaque-runtime recovery, CLI /
fresh-space checks, and final full release gates still prevent landing.

### Independent r16 reproduction passed

The above reproduction completed successfully: runtime ELF, runtime PVM /
ProgramId, and both signed system templates match their pins and staged bytes
from independent immutable exports. `r16-independent-reproduction.log` ends
with `verified Agent-generation all artifacts from immutable sources`; session
60130 is terminal and must not be resumed or restarted for this checkpoint.

The first current-source CLI test build exposed three stale digest arrays in
`vosx/build.rs`. These have been updated to the independently reproduced r16
hashes; the digest checks themselves are unchanged. CLI tests now pass 156,
with one opt-in physical candidate test ignored (`r16-vosx-pins-tests.log`).
Normal CLI rebuilding and that explicit physical candidate test are tracked
separately; no fresh-space startup result is claimed by this test suite.

The normal current-source CLI rebuild completed (`r16-current-cli-build.log`).
Its real `release bundle` and `release verify` commands passed against
`target/r16-release.ziYI98/release-bundle`. The opt-in compiled-runtime candidate
test also passed (`r16-cli-physical-candidate.log`), and its emitted candidate
is byte-identical to the bundled runtime. Thus the ignored test above has a
separate successful explicit run. These checks do not substitute for daemon
startup/restart or ordinary-agent finality integration.

### Fresh r16 first-start and restart ingress evidence

The rebuilt CLI created a fresh isolated `r16-startup` space under
`target/r16-startup.jQHfbi`. Creation prepared the bundled packages and generated
HTTP/SSH-enabled `local.toml`. Only the disposable HTTP port was changed from
8080 (already occupied) to 18080; SSH used 2222. Scratch files remained on disk.

First startup reached `Space daemon ready` at 2026-09-12 22:03:30 UTC (about
78 seconds); restart reached readiness at 22:05:30 UTC (about 120 seconds).
Both returned HTTP 401 to the unauthenticated probe and completed the SSH
host-key handshake. The startup path installs/audits the clean system Agent
before publishing readiness. The script stopped both daemons cleanly; a
socket-capable `ss -ltn` check confirmed neither test ingress port remained
listening, while the pre-existing listeners were untouched.

The original smoke command exited 1 at its final byte-for-byte key-file
comparison: ssh-keyscan banner comments were interleaved differently, while
the actual ed25519 host-key record was identical. The corrected check requires
an actual ed25519 record in each file, filters comments, sorts key records, and
compares them; this check passed on the captured outputs. The disposable script
was corrected for subsequent runs. This is a verified startup/restart and key
persistence result, not a claim that the original script exited successfully.

This checkpoint supports isolated system-bootstrap/ingress testing. It does
not establish ordinary-agent creation/finality, opaque-runtime recovery, full
library/regression closure on this head, or production performance readiness.

### SDK documentation release check

The retained-CLI/negative-surface clean-break script passes on the r16 tree.
There is no generic `doc-check` recipe in this branch; an attempted invocation
was not a successful documentation gate. The new `agent-sdk-doc-check` recipe
builds the public SDK docs with no default features and treats broken intra-doc
links as errors. Its explicit run passes (`r16-sdk-doc-gate.log`), and
`clean-break-check` now invokes it. Scratch files use the disk-backed target
directory. This does not claim whole-book or external-link validation.

The broad library rerun remains active as session 11706, against source
`37d6a5720e7e45e4a19850a16a531e6cb316e299`, with `pvm,private-agent-store`, serial
execution, and socket access. Only the separately tracked long inventory test
is filtered. Evidence is `r16-integrated-library.log`; poll the existing session
before scheduling another run. No final result has been recorded yet.

### Portable SDK lint follow-up

Strict SDK linting (`cargo clippy -p vos-agent-sdk --all-targets
--no-default-features -- -D warnings`) initially reported three manual-contains
and three large-enum-variant errors. The equivalent `contains` checks replace
the three zero-ID searches; all 161 SDK tests still pass
(`r16-sdk-contains-tests.log`). Strict lint remains failed on the three enum
layout warnings (`r16-sdk-clippy-remaining.log`): AuthorityOperationIntent,
InvocationAuthorization, and PrivateRuntimeMutation. No warning suppression or
public allocation/layout change was made. These source-only cleanup edits are
newer than the pinned artifact source and the running full-library checkpoint;
final frozen-source artifact/gate verification remains required.

The three SDK enum layout warnings now have scoped `expect` attributes with
explicit allocation/API rationale. Inline representation is intentionally
preserved: boxing public variants would change constructors and add guest
allocation paths solely for lint. Two regression tests guard inline growth
(authorization <= 1 KiB; intent and Private mutation <= 2 KiB); they are not
wire limits, heap bounds, or performance signoff. Strict all-target/no-default-
features SDK clippy passes (`r16-sdk-clippy-final.log`), and all 163 SDK tests
pass (`r16-sdk-layout-tests.log`). No runtime representation or canonical wire
change was made by the attributes/tests. The integrated library run has passed
the coordinator capacity test and advanced into issuer tests; it remains live
as session 11706, not a completed gate.

### Exact management result carried through replay publication

The full integrated library run described above subsequently completed with
1,663 passing tests; see the current closeout section for its exact source and
excluded test. No test process from that run remains active.

The opaque-runtime recovery work now preserves the exact decoded SDK management
result across the executor/replay boundary, rather than reducing it to a boolean
and discarding the reply. `ReplayExecutor::clean_management_transition_result`
defaults to no evidence; replay rejects missing results and mismatched
success/failure dispositions. Validated `ReplayStep` and publication execution
results retain the reply independently of runtime-private state. The Local
management path now reads its freshly published result from those execution
facts, while retaining the bounded cache for the existing retry/transport paths.

All 53 replay tests pass (`r16-replay-management-result-suite.log`), including
new missing-result/disposition-mismatch coverage and exact opaque-runtime upgrade
and retry publication results. An initial exact-name command selected zero
tests and is not verification evidence. These are host-side changes: no SDK
wire generation or guest artifact was changed.

The combined final rerun passes all **63 replay and Local SDK host tests**,
with no failures, ignored tests or selected tests filtered internally
(`r16-management-publication-final.log`, 14.36s; 1,602 unrelated library tests
were filtered). This includes physical lifecycle, exact retry and restart paths
using the publication-carried management reply. Formatting and diff checks pass.

This is the first part of C1's opaque-runtime closure, not completion: the exact
reply still needs request/receipt-bound host evidence in replay materialization,
canonical checkpoint authentication, pruning/reopen recovery, and consumption
by the Shared/Local projection audits. Do not replace those audits with the
volatile cache or treat publication result accessors as durable checkpoint proof.

### Host-owned management evidence in AJC4 checkpoints

`CleanManagementEvidence` now binds the latest state-changing portable management
input and its Ordered position to the signed receipt commitment, replay request
commitment, epoch/sequence, observed slot and exact decoded result. Replay
materialization carries it through both Local and Shared publication and
checkpoint construction. State/runtime-preserving retries keep the original
mutation evidence, so an older retry cannot replace it or change its clock.

The canonical checkpoint is now **AJC4**, with checkpoint identity domain
`vos/agent/journal/checkpoint/v4`; AJC3, AJC2 and AGJC are rejected. Clean-genesis
checkpoint reopen requires the evidence. Its fields and bounded canonical SDK
reply are included in the checkpoint identity (and therefore an authenticated
Shared checkpoint claim), not an unbound sidecar. The two checkpoint digest
fixtures were refreshed for the new format/domain, preserving predecessor
rejection and domain-separation checks. This is a host checkpoint generation
change, not an SDK ABI bump; committed guest blobs were not replaced.

Shared projection-lag recovery now obtains its disposition from authenticated
replay/checkpoint evidence without decoding Standard private state. The common
comparator still uses the legacy-named disposition value type; this change does
not claim that all Standard-state dependencies in the Local image host are gone.

Verification: **199 passed, zero failed** in
`r16-checkpoint-management-final.log` (40.05s; journal, journal store, replay,
Local SDK host, and physical custom-runtime Shared host selection). The initial
run failed only the expected checkpoint identity fixtures before their update.
A strengthened physical-state-independent regression separately passed in
`r16-checkpoint-management-pruned-source.log`: after another exact retry advances
the fence, GC actually removes the original mutation's Ordered entry, and a
fresh executor with an empty management-result cache reopens the same exact
evidence from the checkpoint. The Shared physical test also verifies the exact
installation receipt/request/result before and after reopen.
The affected CLI clean-space selection also passes **31/31**
(`r16-checkpoint-management-cli.log`); formatting and diff checks pass. These
test builds did not replace the preserved r14 normal CLI binary.

Still required: physical Shared checkpoint certificate/snapshot import and
tampering coverage for the new evidence, production Local opaque recovery,
ordinary-Agent finality, and final frozen-source release gates. Earlier startup
and artifact reproduction evidence is not a final AJC4 daemon smoke result.

### Physical Shared management-evidence snapshot verification

The custom-runtime physical host regression now creates and installs an actual
quorum-certified snapshot after actor installation, completes bounded physical
compaction, and closes the host. It resolves exactly the certified AJC4 file
and independently substitutes five validly encoded variants: receipt commitment,
request commitment, sequence, result, and removal of the evidence. Each changes
the checkpoint identity and prevents cold host reopen under the original
certificate. Restoring the original file restores normal cold reopen with the
exact management disposition and actor material; the subsequent runtime work
still succeeds.

For each variant the test also rewrites the certificate's checkpoint reference
to the substituted identity while retaining its signatures. The altered
certificate decodes canonically, but signature verification against its own
altered claim fails. This exercises content-address substitution and signature
binding separately; it is not a claim of cross-store portable import coverage.
The final selection passes **8/8 tests**, with no failures or ignored tests
(`r16-shared-management-certificate-final.log`, 5.44s): the physical opaque
snapshot regression, cross-store/node/generation certificate isolation, and
all six Shared commit tests. Formatting and diff checks pass. No guest blobs,
runtime ABI, or production source paths were changed by this test checkpoint.

The remaining Local issue is broader than only checkpoint metadata:
`LocalAgentHost` uses the image-backed `AgentDriver`, whose clean Create and
management paths require exact equality with a natively reconstructed Standard
transition. Descriptor and physical-material recovery also decode Standard
private state. The transitional Local journal's opaque-runtime tests do not
prove that production image-backed host supports an opaque runtime. Closing
that production boundary remains required; removing its guards without replacing
their authenticated public-state invariants is not a valid fix.

### Portable evidence and post-snapshot projection checks

The final focused run passes **3/3 tests**
(`r16-portable-management-and-projection.log`, 7.71s), covering:

- The physical singleton-system portable backup path preserves the exact
  management evidence in a different physical store, on subsequent reopen,
  and through all four existing interrupted-restore boundaries (canonical
  marker, staged marker, staged heads, and promoted heads before Raft recovery).
  This fixture uses the Standard-shaped system runtime and the existing
  root-authorized singleton backup protocol.
- The opaque-runtime journal test exports after the original mutation entry
  has actually been collected, initializes a distinct store with its required
  genesis runtime artifact, imports the portable closure, and restores the
  exact evidence and opaque state with an empty executor result cache. Its
  first new import attempt exposed a missing genesis artifact in the test
  setup; adding that required bootstrap artifact fixed the fixture, without
  weakening import checks.
- After certified snapshot/compaction and reopen, the physical custom-runtime
  Shared host's actual projection comparator recognizes the one-installation
  acknowledgement gap and rejects an authority head whose sequence predates
  the installation. It does so without interpreting Standard private state.

These are complementary boundary tests, not a newly supported portable backup
protocol for ordinary or multi-replica Shared Agents. That existing explicit
restriction remains unchanged. Formatting and diff checks pass; this checkpoint
adds tests and a test-only evidence accessor, not production behavior or guest
artifact changes. Production Local custom-runtime support and ordinary-Agent
finality remain implementation work, followed by the final release gates.

### Production Local public directory inspection

`AgentDriver::inspect_sdk_actor_directory` now reads bounded canonical SDK
directory pages from one immutable image through the physical runtime. It
checks the supplied descriptor against the image's public configuration and
runtime identity, fixes the observation slot for the whole scan, rejects
state changes in every lane, bounds page/cumulative counts and cursor progress,
and rejects non-directory outcomes. Local exact-projection actor counting and
one-ack-lag actor enumeration now use this interface instead of interpreting
the Standard actor table. Exact physical-material and management-disposition
checks remain in place.

**11/11 tests pass** (`r16-local-public-directory-final.log`, 8.22s): all ten
Local SDK host tests plus a physical scripted-PVM regression which accepts an
opaque state image and rejects changes to each of its four lanes and a
non-directory management result. The lifecycle/restart test compares the query
to the canonical management page and verifies the stored image is unchanged.
The scripted test deliberately constructs the post-admission driver directly;
it does not prove production custom-runtime Create/reopen. Formatting and diff
checks pass; guest artifacts and SDK ABI are unchanged.

The Local work is still incomplete: descriptor persistence/reopen, physical
actor-material loading, management history, and Standard transition-oracle
comparisons remain private-layout dependencies. The module overview now states
that limitation instead of incorrectly claiming this driver never decodes
runtime internals. Continue replacing those dependencies with authenticated
public metadata and runtime ABI checks; do not simply remove their validation.

### Local physical actor material from the public directory

The production image-backed driver's actor-material loader now resolves the
actor record, immutable install-plan commitment, installation ID and reservation
through the public directory query instead of constructing a native Standard
runtime to inspect its internal actor/installation tables. Runtime package
admission and program-byte identity, signed actor package admission, schema,
policy, installation-data references, runtime capability checks and suspended
actor refusal remain enforced. The producer comes from the verified signed
actor package and is still compared with authority projection during route
validation.

The existing material-recovery test now uses the bundled physical runtime
instead of a scripted stub that could not answer inspection queries. It is
explicitly PVM-gated and verifies immutable installation lineage, package
producer, exact reopen, missing artifacts and substituted process/runtime/policy
bytes. **36/36 driver and Local SDK host tests pass**
(`r16-local-public-material-final.log`, 8.95s); formatting and diff checks pass.

This removes the private actor-table lookup, not every private-state dependency:
the descriptor is still recovered from Standard state before material loading,
and image reopen, management history and transition-oracle comparisons still
need closure. Guest artifacts, ABI and deployment-readiness claims are unchanged.

### Local public descriptor persistence

The image-backed Local driver now persists the canonical SDK descriptor as
bounded public metadata, atomically with configuration and all runtime state
lanes. The new **AGI2** envelope validates the descriptor, its exact configuration
projection and runtime program identity without decoding guest-private state.
Local descriptor reads and physical material lookup use this metadata; public
directory inspection additionally requires the exact stored descriptor.
Management commits update the descriptor together with the state. Old AGIM
images are deliberately rejected; there is no in-place migration.

The storage regression round-trips opaque state through the image codec and
store, and rejects missing metadata, changed configuration, mismatched runtime
identity and the predecessor envelope. The driver/Local/wire run passed
**103/103** (`r16-local-descriptor-image-final.log`, 25.40s). After adding the
exact directory metadata binding, driver and Local host tests passed **37/37**
(`r16-local-descriptor-binding-final.log`, 10.04s); clean-space CLI tests passed
**31/31** (`r16-local-descriptor-cli.log`, 0.43s).
The final **37/37** rerun (`r16-local-descriptor-commit.log`, 9.04s) also
covers refusal of directory inspection without stored metadata. Descriptor-only
changes now trigger a commit as well. Formatting and diff checks pass.

This is storage-format closure, not production opaque-runtime lifecycle
support. Reopen deliberately retains the Standard-state descriptor consistency
check. Create, management history, acknowledgement/invocation validation and
transition-oracle comparisons still need runtime-independent replacements;
removing the existing checks alone would weaken admission. Ordinary-Agent
finality also remains open. The current CLI smoke predates AGI2 and AJC4 and
must be repeated on fresh disposable data after the implementation is complete.

### Local descriptor transitions from public management inputs

Local management now derives its next persisted descriptor from the authorized
SDK request and validated reply rather than decoding the returned Standard
state. Runtime upgrades replace only their selected runtime fields; replica
changes require the exact predecessor generation. Other supported operations
leave the descriptor unchanged. Denials and authenticated retained retries
preserve current metadata, including when a retained upgrade or roster-change
reply predates a newer deployment or roster. Immutable identity substitutions,
wrong reply shapes and invalid descriptors fail closed. The existing exact
Standard transition comparison remains enforced as a separate safety boundary.

All **38/38 driver and Local host tests pass**
(`r16-local-descriptor-transition-final.log`), including physical Local
lifecycle/restart tests and the new public-metadata transition regression.
The first run's new fixture was rejected because its replica list was unsorted;
the fixture now preserves canonical ordering, without weakening validation.
Formatting and diff checks pass. No guest artifact or wire-format change is
introduced in this checkpoint.

Next Local recovery work remains durable management history: exact retained
results, acknowledged-through and decision/epoch high-water marks, and original
observation slots must be host-owned and atomically persisted. A latest-receipt
cache alone cannot replace that history. Standard Create/reopen and runtime
transition checks must then be replaced with public authenticated invariants,
with an opaque runtime tested through the production host lifecycle. Neither
that implementation work nor ordinary-Agent finality is closed by these tests.

### Local management history component

`local_management` now defines a bounded host-owned history and strict LMH1
codec without any private runtime-state decoding. Its retained records include
the complete receipt and request commitments, epoch, decision sequence,
original observation slot and exact SDK result. The latest retained record
preserves the decision/epoch high-water marks; acknowledgement pruning never
leaves an empty history with a nonzero acknowledged frontier.

The transition operation explicitly requires prior independent authentication
and guest-result validation. It rejects changed state or a changed result on
an exact retry, preserves failed unconsumed admissions, refuses consumed
sequences that mutate state, and enforces bounded retention and canonical
clocks. Empty/opaque guest bytes are never interpreted. Codec checks reject
oversized counts before allocating record storage and bound individual results.

The two component regressions pass (`r16-local-management-history.log`, 0.20s):
codec round-trip, late retries, skipped/acknowledged sequences, invalid
acknowledgements, exact-result substitution, full-journal refusal and legitimate
acknowledgement headroom, duplicate commitments and noncanonical clocks.
The combined driver, Local host and history run passes **40/40**
(`r16-local-management-history-final.log`, 8.71s). Formatting and diff checks pass.

This component is not yet wired into `AgentImage` or `manage_sdk`; it does not
close production recovery. Next, persist it atomically with clean Local images,
derive it from verified Create/management transitions, preserve it through
state-only commits, and use it for retry classification and Local projection
comparison. Reopen must reject missing or inconsistent history. Then exercise
those paths through the physical host before removing any remaining Standard
validation boundary. No image format, guest artifact or deployment-readiness
claim changes in this checkpoint.

### Atomic Local management history integration

The **AGI3** image now stores descriptor, bounded LMH1 management history and
all runtime lanes atomically. Verified Create initializes the history;
management advances it from the independently checked request/transition,
including state-changing denials. Invocation/acknowledgement and other
state-only commits preserve it. Clean images without nonempty, canonical
history in the descriptor's authority epoch range are rejected. AGIM and AGI2
predecessors are rejected with no migration.

Production Local retry classification now uses persisted public history rather
than decoding Standard state. The Local one-ack-ahead projection comparator
likewise obtains its exact disposition from that history. Reopen retains an
explicit comparison of every retained record and acknowledgement/epoch/decision
frontier against Standard state until runtime-independent lifecycle validation
is complete; no permissive fallback or history reconstruction is used there.
The old private-state retry helper survives only as a test fixture adapter.

**107/107 history, driver, Local-host and wire tests pass**
(`r16-local-management-image-final.log`, 29.10s). A new physical Create/reopen
regression persists a canonically encoded substituted request commitment,
confirms cold reopen refuses it, restores the original history and confirms
reopen succeeds again. Opaque image codec tests reject missing/empty history
and both predecessor formats. Existing physical lifecycle, expired retries,
staged-create reconciliation and FIFO resume tests pass. Initial compilation
found three test-only module paths needing another `super`; these were fixed
before the passing run. Formatting and diff checks pass.
Clean-space CLI checks also pass **31/31**
(`r16-local-management-image-cli.log`, 0.21s).

This closes persistence and production consumption of Local management
history, not general custom-runtime Create/reopen. The remaining Local work is
replacing Standard admission/transition/reopen checks with authenticated public
invariants, then proving an opaque runtime's full production lifecycle.
Ordinary-Agent finality and final-source release/smoke gates remain open.

### Production Local opaque-runtime management lifecycle

Image-backed Local Create, management and reopen now distinguish the bundled
Standard runtime's additional native parity checks from the public validation
required for every admitted runtime. Custom-runtime state is no longer sent
through the Standard decoder/oracle at those boundaries. Signed receipt and
exact package admission, typed reply binding, persisted descriptor/history,
state bounds, exact retry consistency and management lane isolation remain
mandatory. As in the Local file-store model, the private host-owned image is
the durable metadata authority; its hashes alone are not an external finality
proof. Reopen re-admits the exact signed package/program and catalog closure.

Create now also runs bounded public actor-directory inspection **before**
writing the package or image and requires an empty, state-preserving directory.
That prevents a runtime from publishing preinstalled actors through the Create
reply. The same bounded scanner serves later physical directory queries.

A new physical scripted-PVM regression uses the real `LocalAgentHost` and file
store, not a manually constructed driver or the transitional journal host.
It rejects a forged Create receipt without publishing an Agent, creates an
opaque-state Agent, durably records a management denial, cold-reopens, and
recovers both expired management and original Create receipts without changing
the persisted revision/state/history. Native decoding of its stored state is
explicitly shown to fail. **42/42 driver, Local-host and history tests pass**
(`r16-local-opaque-lifecycle-final.log`, 10.28s); clean-space CLI tests pass
**31/31** (`r16-local-opaque-lifecycle-cli.log`, 0.17s). Formatting and diff
checks pass. Existing Standard parity and substituted-history refusal remain
covered. No guest artifact or wire format is changed by this checkpoint.

This proves production opaque management Create/reopen/retry, not the complete
custom actor lifecycle. Next prove signed actor installation, invocation and
continuation/acknowledgement recovery through this same host, and reconcile
management lane-transition rules with the public ABI for initialization and
migration. Ordinary-Agent finality and the final release gates remain open;
the branch is not yet master-ready.

### Local and journal management lane parity

The image-backed Local path previously rejected every non-Control management
change, including legitimate actor initialization and migration which journal
replay already permitted. Both paths now use one public lane-boundary helper:
successful installation/actor upgrade may change declared requirement lanes,
runtime upgrade may change declared capability lanes, and successful removal
may clear retired actor state. Signed request admission, runtime validation,
typed replies and exact-history checks remain separate mandatory gates; a lane
mask alone is not authorization. Denials may consume authority in Control but
cannot change actor lanes, and inspection preserves all four lanes exactly.

The new regression checks all eight lane masks against each actor lane for
installation, actor upgrade and runtime upgrade, plus denied transitions and
read-only Control mutation. **160/160 driver, Local host, replay and wire tests
pass** (`r16-management-lane-parity.log`, 33.02s), including opaque Local
Create/reopen, checkpoint/replay and the existing exact retry tests. Formatting
and diff checks pass. This removes a concrete Local initialization/migration
restriction; it does not replace the still-required signed custom actor
installation/invocation/continuation lifecycle test or the final release gates.
The physical Shared custom-runtime management/snapshot/reopen regression also
passes **1/1** (`r16-management-lane-shared-physical.log`, 1.27s), exercising
the other production consumer of the common lane rule.

### Opaque Local actor installation and continuation recovery

The production Local opaque-runtime fixture now installs a real signed actor
package and initializes its declared Linear lane. It resolves the actor through
the public directory and verifies recovered program bytes, installation ID,
reservation, incarnation and immutable install-plan lineage. It then yields an
invocation, cold-reopens the file-backed host, refuses a resume with missing
required preimages without changing the image, and completes the exact resume.
A second reopen recovers the actor material and retries the expired install,
original invocation and completed resume without changing the terminal image.

**42/42 driver, Local host and management-history tests pass**
(`r16-local-opaque-actor-resume.log`). The initial installation/invocation-only
version also passed independently (`r16-local-opaque-actor-final.log`, 0.21s).
Formatting and diff checks pass. This checkpoint changes tests, not production
behavior or guest artifacts.

This is a physical scripted-PVM **host ABI/persistence** regression: the actor
package and immutable closure are genuinely admitted, but the custom runtime's
responses are scripted, not proof that it executes the actor's program. It
does not cover positive acknowledgement retirement or target-runtime migration
execution. Those lifecycle edges and application-runtime execution evidence
remain to be closed, alongside ordinary-Agent finality and final release gates.

### Native lifecycle integration audit

After the Local actor recovery regression, the native startup path was traced
again rather than treating library coverage as deployment evidence:

- `vosx/src/commands/space/clean_startup.rs::start_clean_system_agent` creates
  the root bootstrap owner and calls `VosNode::start_clean_agent_production`.
  Its ordinary-Agent `UnavailableAgentFinality` still returns `Unavailable`.
- `vos/src/node.rs::start_clean_agent_production` constructs the system route
  attachment and production owner. It does not open/create a Local host or
  provision ordinary Agents. Separate Local/Shared attachment APIs exist, but
  no call from the examined `vosx` space startup path supplies an ordinary Local
  attachment.
- `RouteHostCommand` in `supervisor_adapters.rs` supports invocation, resume,
  acknowledgement, material preparation and authority projection/reconciliation;
  it has no lifecycle Create/Install command. An attachment for already-created
  physical Agents is not a provisioning workflow.
- `AgentGenesisFinalityVerifier` requires independently authenticated live
  system-Agent history. The older `verify_historical_provision` helper's only
  current call sites are tests, and its documentation explicitly denies that
  validation alone is a sealing capability. It cannot safely replace the
  unavailable verifier by itself.

The separate `CleanSystemAgentControl` is read-only, but it is **not** the
startup attachment used above; its existence is not evidence that all current
ingress dispatch is read-only. The actual supervisor routes already support
actor invocation.

This audit changes the next implementation priority: C2 must connect a durable,
authenticated ordinary lifecycle workflow to the native owner and finality
source. Its acceptance test must start from the same native entry point as
`space up`, create an ordinary Agent, install an admitted actor, invoke it,
restart, and repeat exact retries while preserving authority and physical
state. Keep the existing C1/C2/C3 review grouping. The remaining work is not
merely final tests or artifact repinning, and the branch is not master-ready.

### Local durable application observation for native coordination

`LocalAgentHost::observe_management_application` now provides the physical
observation needed before the existing durable issuer signs an application
acknowledgement. It rereads the private image, requires exact agreement with
the live descriptor/image, finds the exact retained receipt/request result,
reverifies the signed receipt at its original observation slot, and reopens
the admitted runtime/program and actor catalog. Reopen includes normal catalog
reconciliation. Missing artifacts or divergent durable state cannot be replaced
by an in-memory success value.

The host alone constructs `LocalManagementObservation`. It carries the exact
receipt/result, original application slot and a domain-separated commitment to
the complete AGI3 image. The issuer's crate-private Local entry point accepts
this observation and forwards successful results to its existing durable
acknowledgement pledge/sign/retirement machinery; denials are not signed as
successful applications. An observation is a Local storage fact, not system-
Agent finality or route-publication authority.

**21/21 Local host, management-history and clean-issuer tests pass**
(`r16-local-application-observation-final.log`, 13.48s). The physical opaque
fixture checks exact application result/receipt, forged-receipt refusal,
original slot preservation on a later retry, and a changed commitment after
subsequent invocation state. The substituted-history fixture now also verifies
that an already-open host refuses an out-of-band durable image change before
any observation escapes. Existing issuer pledge and recovery tests remain
green; the new Local issuer entry is not yet exercised by a complete native
authorization-to-finalization workflow. Formatting and diff checks pass.

Next connect that native workflow: persist the exact authorized intent, drive
physical application, obtain this observation once, durably pledge its MAA2,
finalize it through the authenticated system authority and publish/reconcile
routes. Retrying after a later image must recover the already-pledged
acknowledgement rather than silently sign a different state commitment. The
Local observation component does not itself complete native provisioning or
ordinary-Agent finality.

### Recover original application acknowledgements before observing newer state

The durable clean issuer now exposes a crate-private recovery operation for an
exact issued receipt. It returns no acknowledgement only when that receipt is
known but has no application pledge. Unknown/substituted receipts are refused.
A pending pledge is signed using its stored image commitment and application
slot; an already signed MAA2 is recovered without consulting the signer. Both
paths reuse the existing exact result/decision validation and crash-safe commit
machinery, rather than rebuilding evidence from today's Agent state.

The Local observation entry point attempts this recovery before pledging a new
observation. Thus a retry after subsequent invocation state cannot silently
replace the already-pledged image commitment. A changed application result is
still rejected, and authority-actor finalization remains mandatory before the
next management decision can be issued. No wire format or artifact changes.

The issuer regressions now exercise recovery before any pledge, rejection of an
unissued receipt, recovery after a failed signer, exact result substitution,
restart with an unavailable signer, and an ambiguous completed storage commit
without resigning. This supports the forthcoming native lifecycle coordinator;
it does not connect native Create/Install or provide ordinary-Agent finality by
itself.
**19/19 clean-issuer and Local-host tests pass**
(`r16-local-ack-recovery-final.log`, 14.54s); formatting and diff checks pass.

### Durable native management intent component

`clean_management_intent` now retains the complete canonical management request
and signed credential call before the future coordinator invokes authority
policy or allocates a receipt. CMI1 bounds both nested frames, binds the call's
authorization plan to the exact request, and checks complete Create target and
authority fields. Construction verifies the credential signature against
independently selected authority/managed routes. Recovery must explicitly
reverify those routes and signature; decoding stored bytes is not authorization.

The dedicated single-writer intent slot uses the existing atomic whole-image
storage contract, but must have a separate physical image from the issuer. An
identical retry is read-only; a different operation conflicts. Any commit error
poisons the instance because the write may already be durable, so recovery
requires reopening the actual store rather than trusting old process state.

**8/8 issuer and intent tests pass** (`r16-management-intent.log`, 3.83s).
The new regression covers canonical round-trip, wrong-route and forged-call
refusal, a write that becomes durable before returning an error, poisoned
in-process retry, exact recovery on reopen, and conflicting-intent refusal
without changing the stored image. Formatting and diff checks pass.

This is the coordinator's pending-input component, not native provisioning.
It intentionally does not claim policy approval, issue a receipt, clear a
completed workflow or publish routes. Next connect its persisted input to the
authenticated authority dispatcher and existing durable issuer/application
observation/finalization stages, including completion and restart handling.
No guest artifact or existing store format is changed by this checkpoint.

### Persisted intent to durable issuance

The intent slot now feeds its stored request and signed credential call into
the existing issuer, after rechecking independently selected routes and the
credential signature. Missing or poisoned intent, mismatched approval and
wrong managed routes are rejected before signing or changing the issuer image.
The caller must supply the configured authority actor's authenticated, durably
applied result; this crate-private adapter does not authenticate actor execution
merely because an approval decodes or matches the call.

The regression reopens both independent stores after signer failure, recovers
the exact receipt, then reopens again and retrieves that receipt without an
available signer. It also checks that an ambiguous intent write cannot issue
through the poisoned live slot. This remains component-level evidence, not a
native authority-dispatch or provisioning test.

**9/9 issuer and intent tests pass** (`r16-intent-issuance-final.log`, 3.59s),
using locked offline dependencies and disk-backed scratch space. Formatting
and diff checks pass. Existing compiler warnings remain; this is not a full
library or release-gate rerun.

The next integration milestone remains one real native ordinary-Agent Create:
durably retain its input, invoke the installed Authority actor, issue and apply
the receipt, reopen the physical result, finalize its acknowledgement through
that actor, and publish its route with independently verified finality. Only
after that path works should Install/invoke/restart acceptance and final release
gates be claimed. No new review batch, guest artifact or store format is added.

### Local target-runtime compatibility before cutover

`AgentDriver::manage_sdk` now physically executes the admitted target runtime's
bounded public directory query against the proposed migrated image before an
UpgradeRuntime commit. The query must preserve all four state lanes and return
exactly the existing actor installation records, including incarnation and
installation lineage. The old runtime's successful upgrade reply alone no
longer causes publication of a target that cannot interpret that image.
Probe errors roll back only newly staged artifacts; the prior image, runtime
selection, descriptor and receipt history remain unchanged. Ambiguous errors
from the subsequent atomic image commit still retain staged artifacts for
recovery, as before.

The existing physical opaque-runtime lifecycle fixture now upgrades through
the actual Local host after actor installation, invocation, yield/resume and
restart. A compatible target commits one revision and resolves the same actor
from its signed catalog after cold reopen. Seven incompatible targets mutate
one of the four lanes, omit the actor, substitute its incarnation, or reject
inspection. Every refusal checks the unchanged live and on-disk image, removal
of the newly staged target package/program, and successful reopen of the old
runtime and actor material.

**43/43 driver, Local-host and management-history tests pass**
(`r16-runtime-migration-regression-final.log`, 12.04s), with locked offline
dependencies and disk-backed scratch space. Formatting and diff checks pass.
An intermediate test-only compile failed on two incorrectly qualified legacy
types; both were corrected before this final run. This evidence covers target
directory compatibility, not execution of migrated actor code or exact receipt
retry through the new runtime. No guest artifact or store format changes.

The native authority-dispatch trace also confirms that its restartable path
must persist the exact prepared invocation and PublicPreflight (including the
original observation slot) before dispatch. Rebuilding that envelope from
current material on retry would change its authorization commitment. Existing
projection-query recovery is not a management authorization/finalization
adapter; native lifecycle integration and ordinary-Agent finality remain open.

### Native management authorization dispatch adapter

The pending intent now uses **CMI2**, retaining the exact prepared Authority
invocation and PublicPreflight as well as the request and credential call.
Decoding binds the envelope to that call's target, invocation, principal,
credential, message and Linear method mode, with no ambient role grants or
runtime state. All nested frames are bounded. CMI1 is rejected rather than
silently reconstructing missing invocation evidence. An identical input retry
preserves its prepared envelope; a different envelope, including a changed
observation slot, conflicts. An ambiguous envelope write poisons the live slot
until a real reopen.

`CleanSystemAgentBootstrapOwner::issue_management_intent` now connects those
stores to the native owner's installed Authority route. It independently
selects the pinned Authority target, verifies the signed input, loads the exact
physical actor/artifact closure, checks the installed public Linear policy,
persists the envelope before dispatch, and submits it through the authenticated
terminal invocation path. Only an exact completed approval reaches the durable
issuer. Recovery rechecks current physical identity/artifacts while reusing
the original persisted preflight. A pending projection conflicts explicitly.

The new tests cover invalid envelope substitutions, an ambiguous completed
write, poisoned retry, recovery without another write, changed-slot refusal,
and predecessor-format rejection. A native-owner test installs the existing
projection-only fixture and confirms that a signed management call cannot
bypass its missing `authorize` policy: no prepared envelope, invocation,
issuer write or signature is produced. The initial test compile missed a
local ServiceWire import; it was corrected before the passing runs.

**39/39 issuer, native-boundary and supervisor-adapter tests pass**
(`r16-native-intent-adapters-final.log`, 5.24s), using locked offline
dependencies and disk-backed scratch space. Formatting and diff checks pass.

This is an internal adapter, **not yet called by the running native lifecycle
entry point**. Positive dispatch with the bundled Authority actor still needs
an integration test. Result retirement, journal-capacity reservation across
authorization/application/finalization, denial handling, host attachment and
route publication remain to be connected before enabling it. The adapter
deliberately leaves the authorization result retained and does not claim
ordinary-Agent finality. No guest artifact was rebuilt in this checkpoint.

### Bundled Authority Create authorization and issuer-size fix

The positive native-owner dispatch test now executes the bundled Authority
PVM, retaining its executable/schema/policy bytes and re-signing only the
package for the fixture's issuer identity. It submits a signed ordinary Local
Agent Create call through `issue_management_intent`, obtains the real actor's
approval and a durable signed receipt, then reopens the separate intent and
issuer stores and retries after expiry. The exact original envelope and
receipt are recovered without another signature or ordered journal entry.

This test exposed a production issuer defect: its 1,024-byte internal decision
limit rejected a valid approved Create carrying both the complete creation
authority binding and the authenticated application context. The limit is now
1,536 bytes; a codec matrix exercises all optional evidence and lane-root
fields with and without the Create binding, round-trips those frames, and
rejects oversized input. The complete issuer image remains bounded at 512 KiB.
The field encoding and CIS2 magic are unchanged. A dev-only `system-authority`
dependency supplies the exact constructor configuration codec; the lockfile
change adds only that dependency edge.

Initial integration attempts also caught two fixture errors: the enrollment
signature must name the founding owner, and the ordinary replica roster must
name the enrolled node owner rather than copying the system bootstrap's
separate transport-principal pin. These were corrected without bypassing
Authority validation. Temporary diagnostics were removed.

**41/41 issuer, native dispatch and supervisor-adapter tests pass**
(`r16-bundled-authority-dispatch-regression-final.log`, 8.43s), including the
expired retry at slot 40 for a receipt expiring at slot 30. The final run uses
locked offline dependencies and disk-backed scratch space. Formatting and
diff checks pass.

Scope of evidence: the Authority actor itself executes as PVM, while this
native-owner fixture uses the existing test-only native Standard outer runtime
and seeds a completed bootstrap predecessor. The intent/issuer stores are
reopened, not the whole owner/transport. This does not prove fresh production
bootstrap, an all-PVM outer-runtime restart, physical application of the newly
authorized Create, finalization, route publication or native ingress wiring.
Those remain required, alongside the existing journal-capacity and lifecycle
completion work. No guest artifact was rebuilt or repinned here.
