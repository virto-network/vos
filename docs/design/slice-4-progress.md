# Slice 4: progress

The log of build step 4, against `slice-4-jam.md`.

## Step 4.0: the JAM probe

**Setup:**
- PolkaJam `nightly-2026-10-13`: polkajam and jamt 0.1.29, Gray Paper
  0.8.0, from paritytech's polkajam-releases;
  - sha256 `10c7c5b3cab366c37a015b82ab437db175c77c4e2dd968d207facda92c170ecd`;
  - unpacked under `~/.cache/vos/polkajam/nightly-2026-10-13/`.
- `polkajam-testnet` with `POLKAVM_BACKEND=interpreter`: six validators
  and one node with RPC on `localhost:19800`.
- **The recompiler run waits for the owner:** PolkaVM's recompiler
  needs `vm.unprivileged_userfaultfd=1`, which is 0 on this machine.
- A probe service, `spikes/sj-jam-b`:
  - `guest/`: the service;
  - `tool/`: links it, runs its refine on our JAM-only host, and
    compares;
  - `probe.sh`: builds, starts the testnet, submits, reads storage;
  - `results/`: what PolkaJam stored, and the comparisons.
- The inner program is one 37-byte basic block: a write to page 16, a
  write to page 17, `ecalli 7`, a write to page 16, halt.

**Fault tracking holds,** identically on PolkaJam and on our host:

| Call | Result | Gas |
|---|---|---|
| `machine` (45-byte blob) | 0 | 1,867 |
| `pages` allocate read-write, 2 pages | OK | 517 |
| `pages` set read-only, 2 pages | OK | 188 |
| `invoke` | FAULT at 0x10000 | 968; 101 inside |
| `pages` set read-write, 1 page | OK | 159 |
| `invoke` | FAULT at 0x11000 | 968; 0 inside |
| `pages` set read-write, 1 page | OK | 159 |
| `invoke` | HOST 7 | 968; 0 inside |

- **The fault address is page-aligned** (the write at 0x11008 reports
  0x11000).
- **Resuming does not charge the block again** (0 inside), and both
  writes land.
- `poke` into a read-only page answers OOB on both hosts.
- **Repairing a written page costs 1,127 gas;** 514 pages cost about
  579K.
- **Arming 2,048 pages** (an 8 MiB arena): allocating read-write costs
  248,083, setting read-only in one call 59,522, setting read-write
  59,522.
- Our runtime also passes the loop directly, on the interpreter and
  the recompiler.

**The counter holds:**
- at the host-call exit, `expunge` returns 20, the instruction after
  the two-byte `ecalli` at 18;
- a machine made by `machine(code, 20)`, its pages and registers
  restored, faults on the store at 20, then halts after the repair,
  with no second host exit;
- `expunge` after a halt returns 0;
- **a machine entered mid-block is charged the whole block again**
  (101 inside, against 25 for the same instructions as a block of
  their own), the same on both hosts.

**Segments hold:**
- two pages exported by one package (each `export` 3,521 gas) come back
  from a later package's imports through `fetch` (kind 6, and kind 5 for
  one item), 171 gas each;
- each is 4,104 bytes, the page then 8 zero bytes, and an index past
  the imports answers NONE;
- imports are named by `jamt item -i wp:<package hash>:<index>` or
  `-i sr:<segment root>:<index>`, and `-e` gives the export count;
- **a `wp:` import works only while the exporting package is in recent
  history, 8 blocks:** one sent later was dropped by the guarantors
  while `jamt` reported it submitted. `sr:` imports keep working while
  DA holds the segments.

**Differences, on our side:**

| Call | PolkaJam | Our JAM-only host |
|---|---|---|
| `gas` | 48 | 10 |
| an unserved call, e.g. `instantiate` | `WHAT`, 1,000 | `WHAT`, 0 |
| `log` | 1,000, and answers `WHAT` | 10, answers nothing |
| `export`, `fetch` in refine | served | `WHAT` |

Instruction gas agrees.

**Also found:**
- **SJ's code-availability race still happens:** the first package
  after `create-service` failed. Because it declared exports, it failed
  on the export count, not with `BAD`, and its exports became zero
  segments.
- **The refine budget** on this testnet is 1,000,000,000 gas a package
  (the Gray Paper's is 5e9); `jamt` gives a lone item all of it.
- **A package holds at most 3,072 imports and 3,072 exports** (12 MiB).
- **Restoring a full 8 MiB arena costs about 2.75M gas.**

**What the plan takes from it** (folded into v2):
- page rows name segment roots, not package hashes;
- the JAM-only host's prices match PolkaJam's;
- a work result never depends on the outer machine's gas;
- the builder checks code availability itself;
- the builder schedules pages within a package's limits.

**Run it again:** `spikes/sj-jam-b/probe.sh` (`build`, `testnet`,
`create`, `item`, `get`, `compare`, `local`), as its usage lists.

## Step 4.2: the compressed tree

**Built:** `vos-tree` (`agent/tree`), `#![no_std]` + `alloc`, building
for the PVM target. Its crate doc is the format's spec.
- **Hashing:** BLAKE2b-256 behind a `Hasher` trait, natively through
  the precompiles crate's software BLAKE2b, which is the precompile on
  the PVM. Tags `vos/tree/{key,leaf,branch,empty,salt,value}`.
- **A leaf** is `H(TAG_LEAF ‖ u16 len ‖ key' ‖ vh)`, with
  `vh = H(TAG_VALUE ‖ salt ‖ value)`. A proof opens leaves as
  `(key', vh)` and never carries a salt, so an opened neighbour shows
  nothing a low-entropy guess could match.
- **A branch** is `H(branch ‖ u16 level ‖ left ‖ right)`. The empty
  tree's root is `H(empty)`.
- **Keys:** `escape`, `ordered`, `hashed` (H128 ‖ escaped key),
  `private`; scan bounds `prefix_end` and `after`. Keys are at most
  8,192 bytes, so every level fits a `u16`.
- **The store:** `NodeStore`.
  - A branch row holds both children's references with their hashes; a
    leaf row holds `(salt, vh)`; there is a top reference.
  - `update` reads every row before writing any, refuses a bad batch
    before its first write, and returns errors rather than panicking.
  - `reachable` lists the rows on the tree, for "no row off the tree"
    checks.
- **Proofs:**
  - `BatchProof` and `RangeProof` are pruned trees in pre-order.
  - A range proof's boundaries are the leaves around it, or the tree's
    edges.
  - `update` from either proof, and `Witness::update` after `verify`, so
    a JAM refine hashes a proof once.
  - A key that prefixes a tree key, or is prefixed by one, is refused,
    since it could never be put.

**Tests:** 23, in one binary.
- Property tests: incremental roots equal a build from scratch, with no
  row off the tree after every batch; proofs verify and every tamper
  fails; updates from proofs equal the store's; `escape` keeps order
  and is prefix-free.
- Named cases: ranges at edges and empty ranges, bounded scans, ordered
  chains growing a level per key, adversarial keys staying shallow when
  hashed, a 1,040-branch path, absent keys ending above a branch.
- Known answers, computed independently from the spec.

**Measured against S4** (hashed `u64` keys, the in-memory store):

| Keys, batch | Hashes per update (S4) | Node rows per update (S4) | µs per update (S4) |
|---|---|---|---|
| 1M, single | 21.3 (21) | 20.3 (20–24) | 21.5 (5.7) |
| 1M, batches of 10,000 | 8.1 (8.1) | 7.1 (7–10) | 10.6 (3.4) |
| 10M, single | 24.6 (25) | 23.6 (20–24) | 34.8 (8.3) |
| 10M, batches of 10,000 | 11.4 (11) | 10.4 (7–10) | 21.7 (6.6) |

The hash counts match S4. The time is mostly the test store's
allocation; outside it, the tree's own time matches S4's pointer tree.
4.3 measures it on the node's rows.

**Reviewed** for soundness (Fable): the format and the three proof
algorithms hold. The fixes it asked for are in: the salted value
commitment, and errors on the store path.

## Step 4.1: requests and replies between agents

**Built:**
- **A message carries a body:** `Call { instance, method, arguments,
  awaiting }` or `Reply { awaiting, answer }`.
  - The answer is `Done`, `Failed { code, detail }` or `Started`. A
    refusal is `Failed` with `Unknown` or `Forbidden`, as outcomes
    already report it.
  - A `Call` that awaits gets its `Reply` in the sender's outbox, on
    the reverse pair, whatever its outcome. An incoming `Reply` is
    consumed in its pair's order; nothing awaits one until 4.5.
- **A message that fails in refine twice alone,** each on a fresh
  snapshot, is proposed as `Input::Failed { from, sequence, awaiting }`.
  - It is consumed as a failed `Ran` step with the code `InRefine`,
    acknowledged, and answered when it awaited.
  - A lone failure is retried first.
- **`Behind`:** a receiver that refuses a gap asks the sender to resend
  now.
  - It is a trigger, never a cursor: the sender rewinds to its own
    acknowledgement, at most once per window per 100 ms, and only from a
    replica of the receiver.
  - A message dropped at a full queue waits for the rounds and their
    backoff, so overload never loses it.
  - The idle sweep goes before `Behind`.
- **The resend round is configurable** (`Config::resend_round`, 1 s by
  default; a window's wait doubles to 16 rounds).
- **`Batch.budget`** carries the refine's gas budget, which the agent
  reads from 4.4 on.
- **The owner's wire items:**
  - the failure and refusal codes are `#[repr(u32)]` enums with the same
    values, an unknown code failing to decode;
  - `PeerMessage` runs 0 to 15 with no gap;
  - the directory acknowledgement's order is `peer::Order { term,
    index, committed }`.
- **A send's price rose** from 4,000 to 5,000 gas: serving the larger
  body costs 3,580.

**Tests:**
- byte pins for codes, messages, batches and every peer message;
- the testkit's requests answered whatever their outcome, replies
  consumed in order, failed messages consumed and answered;
- across nodes:
  - a message failing refine consumed once and never resent;
  - a gap filled within a round trip: under 5 s with a 20 s round, and
    19.8 s without `Behind`;
  - a stale `Behind` changing nothing;
  - a request answered across nodes, and after its leader stops.
- the window's own tests.

**Gates:** `just check` (65 suites); the checker loop all ok; the
faults process tests.

**Reviewed** (Opus): GO with fixes, all in: `Behind` for gaps only,
the sweep first, the compact failed input, the configurable round.

## Step 4.4a: large results as blobs, and `instantiate` at a counter

**Built:**
- **A work result of 64 KiB or more travels as a blob.** Its log entry
  is a new kind, `LargeResult`, whose first reference is the result's
  blob, with an empty body.
  - The leader stores the blob durably, beside the dry run, before
    proposing.
  - Followers fetch it through the existing references, and apply
    reads it off the runtime thread.
  - The dry run's seed check, the apply hooks and `LastResult` use the
    resolved body.
- **No pin:** pins mean "a program the agent runs".
  - The blob is kept by its age until its entry is written, then by the
    log row naming it, then by its age after compaction.
  - A follower writes the row before it fetches, and applies nothing
    past an entry whose blob it lacks.
- **A fetch bug fixed:** a follower's round-robin turn only ever grew,
  so after its first fetch every ask went away from the leader, costing
  a second per large result. Now new blobs go to the leader, and only
  retries rotate.
- **`instantiate` takes the starting counter** in φ8, as `machine`
  does. A counter that starts no instruction answers `HUH`, at the full
  price. A machine back in the pool resets to 0.

**Tests:**
- a 2 MiB result applied on every replica;
- a lagging follower catching up through one;
- a large result's blob kept while the log names it, and collected
  after compaction;
- `instantiate` at a counter resuming a suspended machine exactly, on
  both backends, charged the whole block again, as on PolkaJam (4.0).

**Measured:** debug build, three replicas in one process, four small
agents beside one making about 2.4 MB of results a round:

| | Small p50 | Small p99 | Small max |
|---|---|---|---|
| No large load | 4.2–5.8 ms | 5.5–9.4 ms | — |
| Large results as blobs | 5.3–7.3 ms | 8.6–14.9 ms | ≤ 27 ms |
| Large results inline | 6.7–9.2 ms | 23–31 ms | 0.4–0.6 s |

**Reviewed** (Opus): GO.

**Carried to 4.4b,** before 4.5 puts snapshot pages on this path:
- **disk:** blobs outlive their entries by the 1 h horizon, and the log's
  byte trigger counts only the Raft payload. A short horizon for result
  blobs, and an entry weight vos-raft counts toward `compact_bytes`;
- **a fresh ask requests only the blobs not yet asked,** and a retry
  asks the next member for all;
- **a missing blob under a written row** is lost data, so it halts
  rather than retrying forever.

**Recorded, rare:** the host never calls vos-raft's
`discard_unreported`. A replica holding an entry whose blob no member
still has waits until a restart cuts the entry.

## Step 4.3: tables under key transforms, committed maps, and roots

**Built:**
- **Every table's rows under a transform.** A row is
  `instance ‖ part ‖ tag ‖ transform ‖ transform(key)`, and the agent
  applies the transform itself, so no actor can break the keyspace's
  prefix-freedom.
  - **Hashed** (`H128 ‖ escape(key)`) is the default:
    `pub type DefaultTransform = Hashed;` in `agent/sdk/src/table.rs`.
  - **Ordered** is `Table<K, V, Ordered>`, with keys of at most 64 bytes.
  - A scan returns rows in its table's order, with raw keys.
- **The row ABI:** get, put, delete and scan name their rows with one
  register (`abi::Rows`: the struct, a table or a committed map, with its
  tag and transform).
  - The agent hashes through the precompile, and accumulate hashes
    nothing.
  - `cap::STORED_ROW` bounds a scan's page by the largest row a table can
    hold.
- **`CommittedMap<K, V, T>`** writes reach the work result apart, in
  `Run.committed`. At the version a result makes, accumulate writes:
  - the value row with that version;
  - a dirty row (version first);
  - one seed row per version.
- **The root builder** (`node/host/src/roots`), one task per group:
  - **Its source:** from a snapshot at the state version V, it reads the
    dirty rows past the watermark in batches of 10,000 keys, and salts
    each key with the seed of the version that wrote it.
  - **Its commits:** each batch is one `Change::Tree`, which the writer
    refuses once the agent's epoch has moved. A batch deletes the dirty
    rows it read and the seeds of the versions it has read whole. The
    last batch finishes every map it touched, or that an interrupted
    build left part-way, and moves the watermark.
  - **Recovery:** a failed build is retried, from 50 ms backing off to 5 s.
  - **Proofs:** `Node::prove` answers a `BatchProof` with its leaves
    against a map's last complete root, or `Building` while its tree is
    mid-build.
- **Prices:**
  - a get costs 30k (was 20k), a scan 66k (was 60k), plus 90 gas per
    byte of key, a scan's returned keys included;
  - the escape is word-at-a-time, and zero bytes are cheap in it, so
    keys of zeros, its worst case, keep a fifth of their price spare.

**Found and fixed, older than this slice: a store snapshot could see
part of a commit.**
- **The bug:** in the vendored lsm-tree, a flush or compaction that
  finished on a worker published its sequence number as visible while a
  write batch with a lower one was still inserting.
  - A snapshot opened then saw the batch in part.
  - That reaches the Raft snapshot export (a torn state sent to a
    follower), queries and the root builder, which is how it showed:
    a value row of version 503 in a snapshot at 502.
- **The patch** (support/lsm-tree, `super_version.rs`): a version
  upgrade no longer publishes, so the visible number moves only under
  the journal writer's lock, after the mover's own inserts.
  - Bulk ingestion and fjall's meta-keyspace changes still publish the
    old way, but the node uses neither. `VENDORED.md` and `UPSTREAM.md`
    say so.
  - `torn_snapshots` fails without the patch within a second.
- **For the owner:** a second patch to the vendored lsm-tree, beside
  the first (edf760e3). Keep it vendored, or file it upstream.

**Tests:**
- the testkit: committed rows; both transforms' orders, cursors and
  refills across 300 rows; the ordered key cap; rows at their caps
  scanning back in a later batch; prices with keys of zeros; the model
  agreeing;
- the wire: pins for rows, registers and `Run`; every row key
  prefix-free;
- the tree: escape against a byte-loop reference over zero-heavy keys
  at every alignment. It caught a bug in the first word-at-a-time
  unescape;
- the node: three replicas reach the same root as a build from scratch,
  with every row on the tree, and proofs verify;
  - a follower caught up by snapshot builds the same root;
  - an epoch change refuses a stale batch;
  - a failed build is retried;
  - a map left part-way is finished;
  - an untouched map proves while another builds;
  - `tree_crash`: killed and torn mid-build, it resumes to the root from
    scratch with no row off the tree;
- `torn_snapshots`.

**Measured** (1M keys):

| | |
|---|---|
| A committed write on the apply path | about 4.3 µs: accumulate 1.05 µs on the JIT, the store's two rows 3.2–3.3 µs (a table write 0.46 + 2.7–3.5) |
| The builder at 20k committed writes a second for 30 s | 19.9k rows a second built, a median build of 137 ms, at most 14 versions behind, caught up in 162 ms |
| A build from scratch | 25 µs a key |

Within the 5 µs budget; the builder keeps up near its capacity. A
faster native BLAKE2b in the node is its next lever.

**Reviewed:**
- Fable: the patch and the builder hold.
- Opus: GO with fixes, all in: the scan page bound, the prices with keys
  of zeros, the escape reference test, the build retry, and bounded
  catch-up builds.

## Step 4.4c: result blobs' retention, and a lost blob

**Built:**
- **Blobs have a keep class** in their index row.
  - **Named** blobs go 60 s after their last put or touch once nothing
    names them (`named_blob_horizon`): a result the leader stores, and
    any blob a follower fetches for an entry, whose row it writes
    first.
  - **Aged** blobs keep the 1 h horizon: install programs, and programs
    staged for a snapshot.
  - An old or unknown keep reads as Aged.
- **A result blob is held** in memory from the leader's put until a
  write reaches its entry, so no timing guards that window. Collection
  skips a held blob, and the writer checks again before it removes one.
- **vos-raft weighs data entries** with a host function
  (`Config::payload_weight`, the payload's length by default) toward
  its compaction bytes and kept tail. The node weighs a large result by
  its blob, so blobs no longer pile up behind a log the byte trigger
  thought small. The default weight leaves the simulation's figures
  unchanged.
- **A follower asks for each blob once:** a new blob from the leader,
  and again only after a second, from the next member.
- **A blob missing under a written row is lost data:** the node halts.
  - On restart it never cuts an entry at or below the recovered commit:
    the entry stays in the log, so this replica never votes without it.
    Its blobs are fetched again from the members that hold them, and
    nothing applies past it until they come. If no member holds them,
    the replica stays there, logged as such.
  - Above the recovered commit the cut stays, for the common case of a
    row written whose blob was never fetched or reported. A reported
    entry lost there is acknowledged data lost on disk, which the trust
    model excludes (core model §5).

**Tests:**
- the blob store's keeps and holds;
- one ask per blob;
- vos-raft's weighted counts;
- large results making compaction due;
- a follower turning from a leader that lacks a blob;
- a replica that loses a committed entry's blob halts, then fetches it
  again;
- the review's scenario: a committed entry whose blob one replica lost
  stays committed through the old leader's loss.
  - Both tests fail with the old cut.

**Reviewed:** Opus, GO with fixes. The recovery cut's fix was designed
with Fable.

**Noted:** counting blobs, the default kept tail holds about 4 to 8 large
results, and a follower further behind takes a snapshot. 4.10 measures
it.

## Step 4.4b: what workflows need in the agent

**Built:**
- **Tracked machines** (`agent/default/src/machines.rs`): `track()` arms
  a machine's writable runs read-only.
  - A fault on an unmarked writable page marks it, opens it and resumes;
    any other fault stays a fault.
  - Every write the agent makes into a machine goes through a tracked
    write, and `written()` gives the exact set.
  - The runs come from the program's header (`StandardHeader` in
    vos-pvm-program).
  - Actor runs are not tracked; workflows will be.
- **The agent serves its machines' precompiles** on every host.
  - An inner machine's call exits to the agent, which charges the
    machine the fixed price (600), computes through its own precompile
    (natively on VOS, in software on JAM), and writes the output through
    a tracked write.
  - The bounce costs the agent about 5.0k gas on VOS and 20.0k on JAM.
  - Batches that run actors and hash now give byte-equal work results on
    VOS and the JAM-only host.
- **The prover gates a BLAKE2b call's relations on its acknowledgment,**
  as it already did for its chip. A refine whose inner machine's call
  the agent serves now proves (a new lib test).
  - Each served call costs two of a proof's 1,024 slices.
- **The agent meters its own budget** (`Batch.budget`), never the outer
  gas.
  - A step debits a reserve by kind (a call 300k, an ack 50k, a sweep 1M,
    an install 8M), the gas its handler used, and 64 gas per byte of an
    installed record read on a cache miss.
  - Decoding is paid on top of the budget.
  - 256 small calls take a tenth of a 1e9 budget.
  - **Overruns:** a step that overruns waits for the next batch only
    behind a step that ran a handler; otherwise it fails alone.
  - The node's floor covers a full batch.
- **Programs beside an actor have a kind,** attestable or workflow.
  - Install binds each to a method of its kind, refusing duplicates.
  - A workflow method is never run as a handler.
  - `workflow_program!` builds one, and `vos install --workflow` installs
    it.
- **Prices:** a request's input costs 2,500 (was 2,000).

**Reviewed** (Opus): GO with fixes, all in:
- the prover's gating;
- the meter's record reads and per-kind reserves;
- the overrun rule behind sweeps;
- duplicate installs;
- the node's floor.

**Also fixed on the way** (afe274a7, 8e1cbf43): a replica whose recovered
entries wait for their blobs neither campaigns nor leads, from its first
tick.

## Step 4.5, parts A–D: workflows in the agent

**Built:**
- **The SDK:** `#[workflow] async fn f(ctx: &mut Workflow<Self>, ..)`,
  with no `self`; `#[workflow(role, gas)]`.
  - `Workflow<A>` offers `call`, `send`, `request(..).within(d)`,
    `start`, `result(..).within(d)`, `sleep_until`, `now`, `random` and
    `log`. There is no `checkpoint()`: every `.await` pauses.
  - A pausing operation (REQUEST, RESULT, SLEEP; 8,000 gas each) returns
    only when the agent resumes the machine.
  - A workflow touches no state of its own; it reaches state through
    calls.
  - Compile-fail tests cover the misuses.
- **The workflow table:**
  - rows `w/<id>` (a record with a format byte) and `p/<id>/<page>`;
  - counters, and a pin per program a live workflow runs;
  - a start, by a request or a call, answers `Started(id)`, and its first
    step runs in the same batch when the meter allows;
  - a `Reply` resumes only the workflow awaiting that agent at that
    counter;
  - an owning agent waits for a result with `Body::Wait`;
  - a failure discards the step's effects, consumes its input and ends
    the workflow;
  - ended workflows are collected an hour later through the due index;
  - at most 65,536 live workflows an agent.
- **Snapshots:**
  - the counter from `expunge`, the registers, and every written page
    that differs from its base (the image's data, or zeros);
  - `Run.pages` carries each page's index and hash, and the LZ4 bytes
    travel in the refine output's page section beside the work result;
  - restore instantiates the program at the counter, writes the pages
    back checked against their hashes, and arms the writable runs;
  - the interpreter and the JIT agree on every step's pages and gas.
- **One due index** for session expiry, awaits' deadlines, timers and
  collection.
  - The leader lists its due rows in `Input::Sweep`, and refine checks
    each, never scanning.
  - A row whose workflow is gone or has moved is deleted.
  - A step that could never fit the budget fails with `Cap`.
  - A sleep files at the next millisecond at least, so the head always
    moves.
- **Lost data halts the node.** A workflow record, page or count that
  is missing or corrupt ends the refine through `LOST` (0x483), which a
  VOS node takes as a storage fault and on JAM traps. It is never a
  committed failure of the workflow.
- **The meter prices pages at JAM's cost on every host,** so a step's
  gas is the same on both:
  - a step reserves 400k;
  - arming costs 200 gas a page, restoring 950k a page, and each page
    written 1.1M;
  - a workflow holds at most 768 pages (3 MiB);
  - at the default budget, a step writes about 800 pages, or about 140
    while it holds 768.
- **The depth rule counts the workflow's own machine,** and the stack's
  worst case is 57 KiB of 64.
- **Also:**
  - attests made by a workflow's nested calls are kept;
  - a workflow requesting its own agent traps;
  - `Failure::TimedOut` and `Failure::Unloadable`;
  - an in-place `blake2b_256` in the precompiles crate;
  - `refine.rs` split into `invocation`, `sessions`, `snapshots` and
    `workflows`.

**Tests:**
- 63 agent tests and more, on both backends, each step equal to the
  reference model's.
  - The workflows: transfer, a saga of five awaits, and a 2 MiB
    computation.
  - Replies: foreign, late and wrong ones dropped.
  - Time: deadlines and timers; a sleep ahead of its batch.
  - Lifecycle: traps; pages back at base; an owner's wait; a workflow
    starting another agent's workflow; an upgrade keeping the program;
    the caps and the combined page bound.
  - Effects: a precompile's output tracked across pauses; two steps of
    one workflow in a batch; a nested attest.
  - The due index: orphan and stale rows; a workflow's 62-deep chain;
    lost state halting.
- VOS and the JAM-only host agree, byte for byte, with state served.
- Across nodes:
  - a 2 MiB computation's results traveling as blobs;
  - a saga awaiting another node's agent;
  - pins kept through snapshots and retirement;
  - a lost page halting its node.

**Reviewed:**
- Fable: go. The lifecycle is exactly-once and deterministic, snapshots
  are exact, the wire split is unambiguous, and pins are taken and
  released once.
- Opus: GO with fixes, all in:
  - the stack;
  - the nested attests;
  - the due index's head;
  - lost data halting;
  - the page bound;
  - prices measured (`PAUSE`, `NOW`);
  - `refine.rs` split.

**For the owner, when it matters:** VOS pays JAM's page prices so a
step's gas is the same on every host. If VOS should pay less, the sound
shape is a price table chosen by a package's declared deployment
target, stored in the agent's state, so every replica prices alike.

## Step 4.5, part E: preemption at the awaits, and the follow-ups

**Built:**
- **Units and shares:**
  - a unit is the code between two awaits;
  - effect-free code runs on its workflow's limit as its share;
  - at an out-of-gas exit, which always falls at a block start, the
    step ends with a snapshot and no effects from that unit, and the
    share counts as spent, so the figure is the same on every host;
  - at a unit's first effect (`abi::is_effect`, which the agent and the
    model share), the batch must cover a fresh limit, or the step ends
    with that call pending, served first on resume;
  - pages, and the outputs of calls, inputs, randomness and precompiles,
    are paid before they open;
  - from its first effect a unit is never preempted.
- **The floor:** a step ends early only after it moved since its resume:
  - gas used, at a call;
  - a call served or a page paid, at a page;
  - its counter or registers changed, at an out-of-gas exit.
  - Otherwise it fails, or waits as an overrun.
- **Fairness:** the head due row always runs if it fits, and from it on
  half of what remains stays for the batch's inputs. Requests progress
  in every batch beside two 3 MiB computations.
- **The snapshot holds no gas,** only the pending call (format 2).
- **The page section** is one buffer reserved on first use, with pages
  compressed straight into it, so a full section fits the agent's heap
  at any budget.
- **A missing pinned program is lost data** on VOS (`LOST`); on JAM,
  where the agent loads programs itself, it fails the step `Unloadable`.
- **A reply at or after its deadline is dropped.**

**Probes, on both backends:**
- a machine starved of gas stops at a block start, its gas never
  negative, and resumes there charged that block once, starved plus
  resumed equal to the straight run;
- a machine stopped at a store's fault is charged that block again on
  re-entry.
- PolkaJam's check of both waits for 4.9.

**Tests:**
- a long computation spanning refines on its own at the default budget,
  equal to the straight run, and resumed on a new leader;
- a first effect left pending and served once;
- the floor;
- a call, a compression and an input left pending;
- requests beside large computations;
- a page section near its cap fitting the heap;
- a lost pinned program halting;
- the interpreter and the JIT, and VOS and the JAM host, byte for byte
  across every preemption path;
- the model agreeing.

**Gates:** `just check` (893 tests), the checker loop, the faults
process tests and the fault suite.

**Reviewed:**
- Fable: go. Units are atomic, preemption is deterministic, the floor
  holds, and a pending call is served once.
- Opus: GO with fixes, all in, with 3178a486's own follow-ups.

## Step 4.6: workflows in the replicated node

**Built:**
- **A workflow's owner reads its status and result** (`POST
  /agents/{id}/workflows`, `Client::workflow`, `vos workflow`), signed
  like a query, with a bounded wait.
  - The node reads the workflow's row at applied state, decoding only
    its head, and runs no refine. It is the agent's own owner rule, and
    what a JAM client would do.
  - A stranger, an unknown id and a collected workflow all read
    `Unknown`. A result is kept about an hour after the workflow ends.
  - At most 64 reads wait at once on a node, each for at most 30 s,
    re-reading on the executors at each apply.
  - A read's `not_after` is held within 60 s plus its wait.
- **The exactly-once checker's workflow mode** (the `rounds` actor's
  tours, each round of which does five things):
  - requests another agent's counter and awaits it;
  - calls its own;
  - sends a message;
  - sleeps;
  - computes long enough to be preempted.
  - Each round tallies its own amount, so a duplicate anywhere shows as
    a count of two.
  - Leaders are stopped while a tour awaits and while it computes, its
    refines held so the stop lands inside.
  - Seeds 601–612, all modes, 36 runs: all ok. 0 of 1,927 tours failed,
    across 24 stops mid-await and 24 mid-computation.
- **Across processes:** a workflow awaiting an agent cut off by a
  partition, its own leader SIGKILLed, completes once with its pair
  marks exact.

**Measured:**

| | Quiet | Notes |
|---|---|---|
| Capture plus restore, a typical suspension (3 pages), JIT | 176–252 µs | beyond an empty refine |
| Capture plus restore, 50 KB (15 pages), JIT | 0.62–0.81 ms | 1.47 ms under contention |
| A workflow's resume, a reply in to its step applied, one node | median 1.3–1.6 ms, p99 2.1 ms | synced commits |

- The 50 KB row is within the 1 ms budget, so the live-machine cache
  (decision 4) is not built.
- **Where the snapshot time goes:**
  - hashing pages, one precompile call per 128-byte block: 22%;
  - LZ4: 14%;
  - restore's page loop: 13%;
  - entering and leaving the JIT: 8%.
  - A precompile that hashes a whole page in one call is the lever if
    the row ever needs one.

**Reviewed** (Opus): GO with fixes, all in: the waits' bound and cheap
re-reads, the checker exact under failures, the read horizon.

## Step 4.7: the carried smaller items

**Built:**
- **`#[msg(linearizable)]`:** the schema marks the method. The executor
  decides the marking from the query's own snapshot; a marked query not
  yet past a read index runs again past one, on a follower too. Install
  refuses the mark on anything but a query.
- **`historical_lookup` answers only the agent's own programs:** those
  it pins or its batch installs, and only for its own service id.
  - A pooled program the agent does not own answers as missing, so the
    pool is no way around the scope.
  - The testkit's JAM host follows the same rule.
- **The fan-in bench** (`node/host/benches/fan_in.rs`, three nodes over
  QUIC):
  - **Frames do not bound fan-in, refine does:** the receiver is 97–98%
    busy, about 78% of it in refine, with about 1.1 frames a message
    when nothing drops. So combining agents' deliveries into one frame
    is not built.
  - **A full queue now asks for more once it has room:** the receiver
    tells the senders it dropped, in arrival order, as many as fit, at
    most once per 100 ms. Before it, dropped senders sat out their
    backoff, up to 16 s, while the receiver idled.
  - At 32 senders, the drain after the load fell from 9–26 s to 5 s, the
    receiver 95% busy in it.
  - A `Behind` that comes too soon is deferred, and cancelled if the
    acknowledgement moves meanwhile.
- **An install reserves 9M gas** (was 8M): the schema grew a byte a
  method, and the largest install must keep a fifth of its price spare.

**Reviewed** (Opus): GO with fixes, all in:
- the pool hit scoped;
- the service id;
- the marking decided off the node's thread;
- the drain paced and triggered by room.

## Step 4.8: JAM mode

**Built:**
- **Work on JAM** is a `Work::Package`: the batch, the agent's root
  before, a `StateWitness`, and the imports.
  - The witness holds a multiproof over every key the refine reads or
    writes (each opened absent, read with its value, or written with
    its value's commitment only) and a range proof per scan.
  - `JamOutput` carries the roots before and after, the time, the seed,
    the work result's hash and the export counts.
- **One `apply`** (`vos_wire::apply`) is accumulate's code, run by the
  VOS accumulate, the JAM refine over its witness and the builder over
  its store. Only what a page row holds and the root builder's rows
  differ by host.
- **The JAM refine:**
  - verifies the witness once;
  - serves every read from it and every scan from its range;
  - runs the batch as on VOS, then applies the result;
  - computes the root after, salting each written row from the batch's
    seed;
  - exports the stored pages raw, then the result.
  - Anything the witness does not cover traps, so a wrong witness gives
    the honest transition or none.
- **On resume, a page is imported,** its length checked, and its hash
  compared with the snapshot's.
- **Accumulate on JAM** (told apart by the operand's package hash) swaps
  the root only from the one it stores, and only for a time within the
  slot and the session skew.
- **The JAM-only host** (`refine_host/jam.rs`) serves `fetch`, `export`
  and scoped preimages at PolkaJam's prices, which CI pins.
- **`vos-jam` (node/jam):**
  - the whole-keyspace store;
  - the recording simulation;
  - the witness build;
  - the builder's prepare and accept (accept refuses a package the
    chain did not accumulate);
  - DA (a local stand-in for the segment root);
  - the chain, emulated.

**Tests:**
- **The comparison:** stateful batches, scans of both transforms,
  committed maps, and workflows suspended across packages run on VOS
  and as chained JAM packages, on both backends.
  - The work results are byte for byte equal and the pages equal by
    hash.
  - The roots are continuous, and the builder's rows equal VOS's.
- **The negatives:** each of these traps or is refused:
  - an uncovered read;
  - a tampered value;
  - a range cut short;
  - a written-only key read;
  - unsorted keys or overlapping ranges;
  - zeroed imports;
  - an early or late time;
  - a moved root;
  - a segment DA lacks.

**Measured** (JAM-only host, PolkaJam's prices; software BLAKE2b runs
about 20k gas a compression):

| | Gas beyond the VOS run |
|---|---|
| A witnessed read alone | about 255k |
| A read among 64 in one package | about 192k each |
| A scanned range | about 84–88k a row |
| A workflow package's own work, at most | about 4.9M |

The core model's 25 × 4,760 gas a row was low. A package's own work
falls outside the batch's budget, so the builder must leave room for it
under the refine limit.

**Reviewed:**
- Fable: go. A wrong witness cannot move the root, and the builder is
  trusted only for the batch's content.
- Opus: GO with fixes, all in:
  - `accept` checks the chain stored the root;
  - pages hashed once;
  - `apply` compiled once (the agent's code back to 440 KiB);
  - the JAM host in its own module;
  - the negative tests.

**Decided by the owner meanwhile:** tables are hashed by default, and a
finished workflow's result is kept an hour.

## Step 4.9: the builder, and the JAM milestone

**The milestone holds on a live PolkaJam testnet** (`nightly-2026-10-13`:
polkajam and jamt 0.1.29, Gray Paper 0.8.0, interpreter backend).
- **What was deployed:** the default agent as a JAM service, with two
  actors (the shop, and the counter for a table to scan) and their
  programs solicited and provided as preimages.
- **The workflow:** a computation started in one work package was
  suspended and resumed across three later packages, its pages
  exported and imported by segment root (69 out, 102 in), and ended
  with the result a VOS node gives.
- **Every package checked:**
  - the root the chain stores, before and after;
  - the work result read back from the chain's DA, byte for byte equal
    to an in-process VOS node's;
  - every read witnessed, a table scan by a range proof.
- **Record:** `/tmp/vos-jam-milestone.1T0z2x/builder/record.txt`, with
  `build.txt`. It holds every package's full hash, every attempt with
  its fate and reason, the roots, the witness, imports and exports, and
  the testnet's errors.

| Package | Work result | Witness | Imports | Exports |
|---|---|---|---|---|
| Solicit the programs | 52 B | 2 keys | 0 | 1 |
| Install the counter and the shop | 1,889 B | 4 keys | 0 | 1 |
| Write state | 1,004 B | 25 keys | 0 | 1 |
| Start the computation | 3,471 B | 46 keys | 0 | 35 (34 pages) |
| Sweep 1 | 2,402 B | 40 keys | 34 | 18 (17 pages) |
| Sweep 2 | 2,447 B | 40 keys | 34 | 19 (18 pages) |
| Sweep 3, the workflow ends | 789 B | 42 keys | 34 | 1 |
| Scan the table | 172 B | 7 keys, a range of 12 rows | 0 | 1 |

The refines took 0.26M to 41M gas each, measured on our JAM-only host,
since PolkaJam reports none. That is far within the testnet's 1e9.

**The first run was weaker than this, and the reviews caught it:**
- **The race:** its first package was refused in core, the
  code-availability race 4.0 found, and the builder's retry landed it.
  Its record did not show the refusal.
- **The equality check:** it compared the builder's simulation with VOS,
  not the chain's own result.
- **The fixes:** the builder now waits two slots past the code's
  availability, and the record lists every attempt. In an experiment a
  package anchored at the preimage's own slot was refused 2 of 2 times,
  and one a slot later landed 5 of 5. Equality is now checked on the
  chain's bytes.
- Two later runs landed every package at its first attempt.

**The builder (`vos-jam`):**
- **The store:** persistent (fjall), holding rows, the tree and pages'
  export locations. A package in flight is an overlay of what it
  touches, committed in one synced batch.
- **Its loop:** prepare (simulate, witness, fit), submit through `jamt`,
  wait by the package's time window, then accept or recover.
- **Accept and recovery:**
  - accept reads the result back from DA and requires the root the chain
    stored;
  - a refused package is rebuilt at a new time;
  - a package that landed late is taken, its result kept;
  - one landed by another builder is taken from its exports if it
    reaches the chain's root; more than one behind stops with
    `Diverged`.
- **Fitting a batch:**
  - gas: the package's own work (verifying, applying, the root after,
    exports) is estimated, and the batch's budget leaves it room under
    the refine limit;
  - batches, a sweep's due rows included, are trimmed to 3,072 segments
    and 12 MiB;
  - a workflow whose pages left DA is left due, and the rest proceeds.
- **The chain:**
  - accumulate on JAM also stores the last package's exports record
    (the guarantor's segment root), which is how the builder learns
    where pages live, and solicits the preimages a package names;
  - the builder reads the chain at one finalized head;
  - transient RPC errors are retried, and `jamt` runs with a timeout.
- **Run it again:** `just jam-testnet` (`just jam-milestone` when this
  ran). It needs the PolkaJam binaries and systemd-run, so it stays
  outside `ci`. The builder's logic is in `ci` against the emulated
  chain.

**Probed on PolkaJam** (spikes/sj-jam-b), agreeing with our runtime on
all 14 records:
- a machine starved of gas stops at a block start, charged nothing of
  it, and is charged that block once on resume;
- `expunge` at a faulting store gives the store's counter, and
  re-entering there charges the whole block again;
- `solicit` is host call 24, and the solicit, provide, lookup flow
  works;
- `historical_lookup` costs 1,125 plus 264 a KiB, now our JAM-only
  host's price too.

**For the owner:** PolkaJam's recompiler needs
`vm.unprivileged_userfaultfd=1`, so the milestone ran on its interpreter.
Our own runtime passes on both of its backends.

**Reviewed:**
- Fable: go. Nothing lets a builder move the root to a transition the
  witness does not produce, nor double-apply an input.
- Opus: GO with fixes, all in. The availability race, the equality on
  the chain's bytes, late landings, trimming sweeps, finality, and the
  record were all fixed, and the milestone was rerun.

## Step 4.9b: one actor, one ELF

**Built,** to the design Fable reviewed and approved:
- **One crate, one build, one ELF.** `vos install --elf actor.elf`
  uploads it as it is, and the platform derives the rest. No program per
  workflow, no crate per attestable.
- **Workflows live in the actor's program.** A workflow's first step
  starts it at instruction 0 with the method, its kind and its
  arguments' length, and `dispatch` routes it. Its record names the
  method (format 3).
- **Attestable methods** are `#[inline(never)]` entries listed in a
  `VOS_ATTEST` table of (method, entry). A table, not exported symbols,
  so dependencies with attestables of the same name never collide.
- **`derive(elf)`** (`pvm/compiler/src/derive.rs`, transpiler version
  1):
  - **The actor's program:** today's link, byte for byte.
  - **One kernel per attestable method:** the code and data its entry
    reaches through relocations and branches, behind a prologue.
    Unreached data is zeroed in place.
  - **What it refuses:**
    - an ELF without relocations, with an unknown relocation type, or
      with more than one code section;
    - a kernel that reaches a host call other than a precompile, its
      call chain named.
  - **Pruned code traps:** a pointer into pruned code goes to an address
    no jump table holds, a branch to a trap, and every kept span ends in
    a trap.
  - **Bit-reproducible:** tested across processes with different hash
    seeds, and the hashes are pinned on a committed fixture.
  - **Bounded:** work grows with the ELF once and with each kernel's
    reach; a crafted 17 MiB package derives in 267 ms.
  - **Fuzzed:** 256 cases in the suite, more by
    `VOS_DERIVE_FUZZ_CASES`.
- **The node derives on an executor:** a panic fails the install, not
  the node. It proposes `Admin::Install { instance, derivation, roles }`
  with `Derivation { program, kernels, elf, transpiler }`, one
  constructor shared with the JAM builder. The agent binds each
  attestable method to exactly one kernel.
- **`ctx.read(|actor| ..)` and `ctx.update(|actor| ..)`:**
  - sections on the workflow's own instance's state, opened and closed
    by `OPEN` (0x540) and `CLOSE` (0x541), 3,000 gas each;
  - inside one, only that instance's GET, PUT, DELETE and SCAN, with
    NOW and LOG, are served (`abi::workflow_may_use`);
  - anything else traps, as do a second open or a halt while open;
  - a section is an effect for preemption;
  - neither closure can reach the context, which the types forbid.
- **An actor's heap is paid by every invocation of it:** arming on a
  workflow step, and on JAM the heap's pages on every call. So actors
  keep small heaps, and a test needing a big one installs a big build
  of its actor. A heap mapped per kind of invocation is carried to a
  later slice.
- **The core model's** §6.4, §6.5 and §11.1 now say so.

**Kernels:** the ledger's `checksum` kernel is 5,654 bytes, against
5,103 as a program of its own. The test actor `kernels` derives through
a vtable, a real switch table (11 ADD32/SUB32 pairs) and a precompile
with its software fallback.

**Tests:**
- reproducibility, the pinned fixture, bounds and fuzzing;
- kernels run alike on VOS, the JAM-only host and the model;
- sections atomic, misuse trapping, compile-fail cases;
- a workflow resuming on its own program through an upgrade, on VOS and
  on JAM;
- the milestone rerun on derived programs: every package landed first
  time, equal to VOS.

**Reviewed:**
- Fable: approve. Then three should-fixes, all in: the heap's cost
  stated, an unreadable span refused, the fuzz count true.
- Opus: GO with fixes, all in:
  - derivation linear;
  - `read` unable to reach the context;
  - a real switch table tested;
  - unknown relocations refused;
  - one section rule;
  - one `Derivation` constructor.

## Step 4.10: acceptance, the end review's fixes, and the closing cleanup

**Acceptance on the slice's code (145c893c):**
- `just ci-full` green: 127 test binaries, 1,281 s.
- **The checker loop with workflows:** seeds 601–612 across the three exactly-once tests (one request at a time, pipelined, workflows), with leader kills. All 36 runs green, 949 s.

**The end review (Fable): "close with named fixes first".** Each finding:
- **F1, the record and the core model:**
  - §9.3, §12 and §14 brought to what was built and measured (fd618865);
  - this entry;
  - §8.2 and §8.3 rid of the explicit `checkpoint()` the owner replaced with "every `.await` may pause".
- **F2, workflows whose pages DA lacks:** found in one pass before the first simulation, with pages fetched once per package (4.10a). Re-export before retention, or a deterministic pages-lost failure, is carried to slice 5.
- **F3, the builder's budget below the VOS floor** (4.10a):
  - a batch starts at the refine gas less a pinned bound on the package's own work, 900M of PolkaJam's 1e9;
  - it never drops below `min_refine_gas`'s floor while it can shrink;
  - a lone input is retried at the floor;
  - a chain whose refine gas gives less is refused.
  - `HELD_PAGES` went from 768 to 576 pages (2.25 MiB), so the step ending a workflow at the cap fits a package. That is const-asserted (about 913M of 950M usable).
- **F4:** `vos-checker`'s tests run in `test-agent`, and the loop was rerun on the final code.
- **F5, PolkaJam's re-probe on upgrade and the recompiler run:** carried to the owner.
- **F6:** the 4.4a note on a replica waiting for a blob no member has is corrected. It waits for good, logged, which the crash-fault trust model (core model §5) accepts.

**Also in 4.10a:**
- **An ingress bug, reachable without a token:** a 64-byte non-ASCII bearer token sliced inside a character and panicked, and each panic leaked a connection slot until the ingress refused everyone. `hex32` now refuses such tokens, and a drop guard releases the slot.
- **One refine-host lookup** (`serve_lookup`) serves the node, vos-jam, the JAM reference and the testkit, so the reference charges the node's lookup gas.

**The code-quality cleanup (4.10b–f),** behaviour-preserving, each step reviewed by Opus with its fixes folded in:
- **4.10b, the agent crates:**
  - the definitions the agent and its model share move into the wire (an `Op` enum, `Outcome::failed`, `ids::derive_id`, pinned by known answers);
  - the large files are split;
  - the meter is encapsulated;
  - one `Call` struct travels through invocations.
- **4.10c, the PVM and support crates:**
  - every emitted program byte-identical, with derive's pinned hashes unchanged;
  - dead RV32 paths, a dead pass and duplicate scans removed;
  - the linker split into phases;
  - the refine host's handlers use `?`, with one dispatcher;
  - the review restored a refusal derive had lost, for a kernel jumping into its own prologue.
- **4.10d, the node's core:**
  - the leader, node, driver, raft and storage split;
  - one `send` that derives its class;
  - `Change::synced` lists every variant;
  - the leader's outbox recovery is retried under backoff.
- **4.10e, the node's edges and storage:**
  - blobs, client and store split;
  - the blob collector reads references without decoding bodies;
  - one client lock with no lock held over I/O;
  - the benches moved to `benches/`.
- **4.10f, jam, cli, checker, net and the test harnesses:**
  - shared helpers in `vos_checker`;
  - `vos jam milestone` is now `vos jam testnet` (`just jam-testnet`);
  - clap value parsers;
  - signed-call construction in one place.
- **New gates:**
  - `just doc-check` (broken and private intra-doc links, in `check`), which fixed 153 links;
  - `fmt-check` over the crates the workspace excludes.
- **Test flakes fixed, each guarding what it did:**
  - a down node's port taken by another listener (the harnesses hold it);
  - the snapshot stream outlasting the leader's deadline;
  - head-of-line blocking bounded by a bulk frame's time;
  - the restarted follower's probe;
  - test installs following the leader on `NotLeader`.
- **Lines:** the steps moved about 25,000 lines into new modules. The net count barely moved: the module headers and the named helpers ate the removed duplicates.

**Final gates on the cleaned code (83775f0f):**
- `just ci-full` green: 126 test binaries, 1,464 s.
- The checker loop with workflows: 36 runs green, 878 s.
- An earlier full run, on 7745cdab, failed once: a restarted node in the
  served suite found its port taken while it was down, under heavy load.
  The harnesses now hold a down node's ports, and `free_port` never
  hands one out twice. The rerun is the one above.

**Open for the owner:**
- **A step's own effects on JAM.**
  - At the agent's per-step caps (writes, 16 messages, 16 attests), a step's effects cost up to about 1.15e9 of a package's own work, and the worst step about 2.06e9.
  - A lone step whose effects pass what its keep leaves fails `Cap` on JAM only.
  - One past the usable gas leaves the builder no package to make.
  - A request's step is left undispatched instead.
  - Closing it needs per-step effect caps about 31 times lower for agents on JAM.
- PolkaJam's re-probe on an upgrade, and its recompiler, which needs `vm.unprivileged_userfaultfd`.
- VOS paying JAM's page prices.
- The lsm-tree patch: kept vendored, or offered upstream, before master.

**Carried, each to a named slice:**
- **Slice 5:**
  - DA re-export before retention, or a deterministic pages-lost failure;
  - a workflow's resume latency on three processes, and 4.4c's follower catch-up figure;
  - a heap mapped per kind of invocation (a bump allocator over the header's heap region);
  - the private key transform;
  - the per-step effect caps for JAM agents, with the owner's decision.
- **Before master (the owner's "very end"):** the spikes, the vendored lsm-tree and the rest of the cleanup list.
