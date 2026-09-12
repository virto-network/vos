# Reviewing the Agent architecture saga

Current Ch08 WIP warning: `wip/ch08-runtime-directory` has independently
reproduced r16 bundles and passing fresh-space startup/restart ingress checks,
but ordinary-agent finality, opaque-runtime recovery, and full release gates
remain open. This is not a master-ready branch.
See the current closeout plan below; later checkpoint sections retain historical
results, including failures that have since been fixed.

## Current closeout plan

Implementation is in `.worktrees/ch08-runtime-directory` on
`wip/ch08-runtime-directory`, not yet in the root `saga/agents` checkout.
Use only an isolated, disposable environment for bootstrap/ingress testing.
Fresh-space first start and restart with bundled system actors and HTTP/SSH
have passed; ordinary-agent creation is not yet a usable production path.
Those ingress checks predate the new AJC4 host checkpoint format. A newly built
CLI needs a fresh disposable data directory and another smoke run; AJC3
checkpoints are deliberately rejected, with no in-place migration provided.

The integrated library run at `37d6a5720e7e45e4a19850a16a531e6cb316e299`
completed: **1,663 passed, zero failed, one filtered**, in 1,771.43 seconds.
It used `pvm,private-agent-store`, serial tests and socket access. Evidence:
`.worktrees/ch08-c2-native/target/task-tmp/r16-integrated-library.log` (path
relative to the main checkout). The filtered large inventory test still needs
a final-source run. Later SDK lint-only edits have separate passing SDK tests
and strict clippy, not a completed full-library rerun on those edits.

Keep the remaining work in three scoped Chapter 08 batches, without adding
review endpoints for individual fixes:

1. **C1 — recovery:** preserve the integrated portable-recovery fixes. Host-owned
   management evidence now survives checkpoint/GC/reopen and feeds the Shared
   projection comparator. Physical Shared certified snapshot/compaction and
   substituted-evidence reopen checks now pass, as do portable evidence
   preservation and the post-snapshot one-ack-lag projection checks described
   below. Close remaining Standard-state dependencies in the production Local
   path. Neither a private-state decoder nor a volatile cache is a
   runtime-independent proof.
2. **C2 — native lifecycle:** replace the deliberately unavailable ordinary-
   Agent finality adapter with authenticated live system-Agent decision
   publication and independent replay verification, including reopen. A
   self-consistent provision or a permissive verifier is not sufficient.
   Prove ordinary-agent creation, actor installation and restart end to end.
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
