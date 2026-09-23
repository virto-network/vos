# Experimental state-tree probe

Test-only guest, not an installable or released AgentRuntime. It uses the SDK
row/tree reader and verifies the selected root and fetched blocks inside the
PVM, then returns candidate blocks for incremental replacements/deletions. It
reuses the portable guest allocator, but does not use the r19 runtime dispatcher.
The lookup key is fixed. Raw primitive tests use fixed identities; execution
frames select the actor identity and contexts from their request.

Experimental ABI 003 uses an explicit StateLane selector in fetch register r11
(guest a4) and explicit signed-package quota limits in its execution frame.
ABI 001/002 artifacts are incompatible; the released r19 contract is
unchanged. The probe also has a test-only Create branch that initializes rows in
every declared data lane. This is not production lifecycle or authorization logic.
Create, Invoke and ACK maintain a lane-wide row/byte counter in the same tree
candidate as their row changes. Invoke writes two rows on Linear or Local.
The guest consumes the frame's quota limits, which typed host execution matches
to the admitted signed package; it has no compiled-in quota default.
ACK writes a small invocation-keyed marker
and returns the exact work/authorization commitments. This marker is deliberately
not a production retained-result store; it exercises ACK binding and
changed-root publication without claiming complete runtime semantics.

The ignored replay test `compiled_external_checkpoint_publication_reopen_and_gc`
uses this compiled guest's signed-package execution handoff through suffix replay,
real checkpoint preparation, disk publication, interrupted staging/reopen and GC.
It is included in `just test-agent-state-prototype`. The initial runtime selection
is synthetic; this is not a runtime-upgrade or production authorization test.

`compiled_external_genesis_preparation_authenticates_and_retains_roots` starts
from actual authenticated experimental Create, then uses a pinned session for
Linear/Local mutations and ACKs on memory/file stores. It covers interrupted
publication, exact retry, file-handle close/reopen, read-only budgeted recovery
and missing-block refusal. It also checkpoints, continues work, checkpoints again
and collects unreachable file blocks in bounded passes before reopening. The
initial Merge root/frontier must remain unchanged; this does not admit Merge
execution. Mutation and checkpoint faults cover ObjectDurable, HeadsStaged and
HeadsDurable, including a durable commit whose response was lost.
Recovery freshly executes the signed guest using read-only persisted blocks and
the aggregate recovery read budget. The test clears its capture list before the
first recovery and checks that failed authentication prevents guest execution.
Invocation authorization and retained-result semantics are still fixtures;
this is not released-binary or process-restart qualification.

The file-backed test uses explicit experimental `XSW2`/`XST1` execution frames:
a canonical journal Invoke carries its base and expected next root context,
derived from test-admitted genesis/provenance and the selected successor cursor.
The response binds the exact request, transition and candidate blocks; the host
converts it through ordinary replay transition/lane checks before staging.
Both physical fixtures wrap the compiled program in a signed test package and
run signature/closure/PVM-host-call admission. The journal adapter compares its
complete admitted identity (deployment, program, producer, package, ABI and
execution semantics) before loading or fetching; substituting any field fails.
Experimental journal decoding requires the exact ABI/semantics pair; ordinary
r19 installation still refuses these packages. The file-backed fixture uses a
synthetic post-upgrade projection retaining its predecessor's original root:
it does not perform or qualify bootstrap, runtime upgrade or installed lifecycle
authority. That standalone block-staging fixture publishes no heads; the replay
fixtures above do. Production ABI/gas policy remains open.
The typed physical entry executes the admitted package's exact program and
checks runtime deployment, lane capabilities and signed input/output state-byte
limits. Its compiled regression covers a valid update and refusal of mismatched
deployment, unsupported lane, oversized input and oversized returned state.
Failure never stages candidate blocks. Resume and management are unsupported
at this entry pending their lifecycle/retained-owner bindings. Raw-program
execution hooks and the old unadmitted journal bridge are test-only. Physical
replay of the experimental contract requires an exact execution capture; it
cannot substitute an ordinary opaque transition without that evidence.
It rejects responses replayed against different work. This fixture also retains its
small raw read/write protocol for primitive tests; neither protocol is admitted
production runtime dispatch. Journal Invoke/ACK supports one external lane per
call; admitted Create routes all declared lanes under one shared budget.
Attested reads remain unsupported. Runtime authorization and real
continuation/lifecycle qualification remain separate integration work. This
guest deliberately does not implement admission or authorization; it is a row
updater for tests, not a deployable runtime. The obsolete Resume-with-Ready
fixture branch was removed; retained-continuation execution is not qualified.

From the repository root, with disk-backed `CARGO_TARGET_DIR`, `TMPDIR` and
`JUST_TEMPDIR` (the latter two may use the target's `task-tmp` directory):

```sh
just test-agent-state-prototype
```

The physical tests check value/absence lookup amid unrelated rows, replacement
and deletion parity with native SDK execution, preservation of old snapshots,
no provider mutation on output failure, rejection of
a substituted root commitment, and guest rejection of stale block bytes from a
deliberately dishonest host. Candidate bytes are not committed heads or
availability certificates. A disk-backed journal test runs the compiled guest
through an audited staging session and verifies candidate parity, persisted
blocks after reopen, old/unrelated row retention, and unchanged files/root on
gas, output-size and staging-budget failures. It never publishes a journal head.
Staging consumes the captured execution directly and rejects a stale base. A
second execution writing the same value at a later position returns no change,
retains the old descriptor, and stages with no reads or writes. This is a data
no-op test, not journal retry/deduplication or continuation qualification.
Ordinary tests separately check pointers, budgets and host verification. This
does not qualify authoritative root publication, power-loss recovery, Clerk,
quorum, backup, proof production or production throughput.

The same command also runs the physical growth regression at 16, 256, 4,096 and
100,000 rows. It measures fixed-key lookup, four-byte replacement and deletion
using the compiled guest, comparing complete candidates with the native SDK.
Native fixture construction is outside timings; the provider is in-memory and
retains historical blocks. Each operation is limited to 32 fetches / 8 KiB of
fetched bytes and 8 KiB of response, with a separate 512-fetch / 64-KiB limit on
incremental reuse verification. These are fixture-specific regression ceilings,
not limits promised for adversarial keys or larger values. Output reports actual
gas and separate load, run and verification time; timings are diagnostic, not
asserted service-level targets. This does not measure guest allocator high-water
use, journal durability, Clerk's multi-row work or concurrent serving capacity.

The fixture lockfile pins its own dependencies; it is not a production artifact
pin. See `docs/agent-saga-status.md` for the single live plan and open gates.
