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
