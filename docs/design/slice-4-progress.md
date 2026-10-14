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
