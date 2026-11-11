# Open: known gaps and next work

The one forward-looking list. Each item names the gap, what is known about
it and where its design lives. The design docs describe what is built;
anything they mark "not built" or "open" is here.

## Performance and scale

The scale results are in `core-model.md` §14, "The scale test".

- **Client latency at the users target (T1).** The best p99 at 10^6 users
  and 4,000 transfers a second is 1.31 s against a 50 ms target. The levers
  not yet taken:
  - the gap between a batch's commit and its apply;
  - the fsync on a disk the nodes share, and its write amplification
    (re-measure on separate disks);
  - batched signature checks on the executors.

  Several batches in flight per group is built and off by default: it pays
  only with cheaper batches or appends pipelined to followers.
- **The soak's p99 drift (T6)** with the state on a shared disk: commit p50
  56 → 92 ms and fsync mean 28 → 40 ms over two hours. Re-measure on
  separate disks.
- **Recovery throughput (T5).** Throughput back to 80% within 30 s of a
  node's restart missed (33–36 s), driven by the driver's 30 s call
  timeout and the restart's catch-up at the knee. Killing a whole host (as
  opposed to a node's unit) needs a second node machine.
- **Headroom on several hosts (T2).** The knee on four or more node hosts
  is unmeasured; one host's knee was not re-measured after the last levers.
- **Leaders unbalanced after a cold restart** (45,621 / 29,961 / 24,484 of
  100,066 groups; p99 8.4 s against 1.3 s). No leader rebalance exists.
- **Window proportionality (T4).** The representative's work per reader is
  not separated from the rest.
- **Stale sessions past the soak's hour:** 120 `Expired` / `StaleSession`
  refusals for sessions the agents expired while the driver still held
  them. Not investigated. Whether a client resumes its session after a
  timeout instead of opening another is the client's design.
- **Budgets not re-measured over the node API:** the replicated agent's
  rate (at least 20,000 calls a second, p99 within 10 ms) is at its edge,
  a follower query's p99 misses its 100 µs, and many active agents (64
  agents at 40,000 a second) misses (`core-model.md` §14).
- **The storage engine's tuning:** compaction under sustained writes, cache
  sizing per node, cold reads (`core-model.md` §9.5).
- **Placement:** agents placed and rebalanced through membership changes.
- **The executors' verification gate** (`node/SECURITY.md`, "Denial of
  service": at least 100 credentialed verifications a second per
  verifying thread, scaling linearly): a device proof's verification
  alone takes about 12 ms on a quiet x86 core, past the 10 ms a call
  that rate leaves, so the gate's rate for device proofs is the owner's to
  restate (the bench drives `50·k`); its own run, the node pinned to a
  many-core host's performance cores and the generator on another machine
  over QUIC, is not done. A bound per verification under full
  load (within 5 ms on average) is not yet a gate.

## Proving

- **The device prover's next levers:** format 47 takes word-level memory
  and the per-program CPU (`proving.md` §8). The per-program CPU for node
  segments is later. The 4-way CPU split by opcode family is not built.
- **The ledgers' padding** [reviewed, 2026-11-10; resolved for device
  proofs by format 47]. `MemoryChip` fixes no place for its padding and
  its sortedness gadget does not fire across a padding row (`both_real`
  zeroes the ordering delta), so its real rows may be several sorted
  runs; every run starts with a `ts = 0` write (`IsGroupStart`, also on a
  padding→real step) and every group ends with a closing read
  (`IsGroupEnd`, also on a real→padding step). A byte is one group, and
  its reads the last write's or its first touch, when its boundary
  produces its `ts = 0` write once. Per ledger:
  - **Segments (41, the AIR 32's leaves verify):** consistent. A byte's
    boundary tuples are its listed page's alone (the CPU's, the
    precompiles' and the witness input's carry 0 in the last field and a
    timestamp ≥ 1, the verifier's `initial_state.timestamp ≥ 1` and the
    chain's entry at 1), and a page is listed once: its 32 aligned rows
    are real together, its leaf `(20, index)` is produced once, and the
    `MerkleNode` balance down from the root's one consumption takes each
    index once. The register ledger: a chain starts only with a register's
    `ts = 0` write (`ChainStartH`), the boundary chip's thirteen, bound to
    the public registers. The program memory is a preprocessed read-only
    table. Padding inside both ledgers verifies, harmless (gate
    `segment::gates::padding_between_the_ledgers_real_rows_is_harmless`,
    on the segment AIR proved masked). The masked segment verifier
    refuses a first timestamp below 1 as the unmasked one does (gate
    `segment::gates::a_first_timestamp_of_zero_is_refused`). 28, 32 and 39
    prove the recursion AIR, which has no memory argument.
  - **Device 46: not consistent; retired behind 47.** `DeviceMemoryChip`
    lets a byte have as many rows as the prover puts (its address bits
    free, no ordering, `Last` and `ClosingTs` free), so a byte can have
    two groups, each in a sorted run of its own and started and closed by
    its own boundary row: a read in the second sees the byte's first
    touch, or any write placed with it, instead of the last write before
    it. It needs one spare `DeviceMemoryChip` row and about four spare
    ledger rows at the program's log sizes (auth's ledger: 12,754 of 2^14
    rows). In one sorted run a second boundary row does not balance (its
    `ts = 0` write is no start, and only a start consumes the permission),
    so the gap needs both. On paper a riscv64 kernel's stack spill reloads
    its first touch (zero) or an older spill, so a value the kernel's
    control flow reads back, a check's result among them, could be
    another. Its register ledger (`DeviceBoundaryChip`'s preprocessed
    registers, entry at timestamp 1) and program memory are consistent.
    Gate `device::memory::byte_ledger_padding_between_real_rows_is_accepted_today`
    holds the byte ledger's acceptance of padding inside it (the shape's
    byte ledger) and flips if the ledger takes a last-row column. Format
    47's release retires 46 at once (`DEVICE_FORMATS`: 46's date 0), so a
    node refuses a 46 proof `Format` unless its configuration admits 46
    (`Config::device_formats`, which the window's gate uses); 46's code,
    fuzz target and leakage gate stay until it is deleted. Device proofs
    are in no leaf, fold, wrap, venue or `MANIFEST` pin.
  - **Device 47 (the word ledger):** consistent. `IsLast` keeps padding
    past the real rows, one sorted run, a word one group; a second
    boundary row's `ts = 0` write has no start to consume it (gates
    `padding_between_real_rows_is_refused`,
    `a_word_touched_twice_at_the_boundary_is_refused`); and the last row
    is padding (`IsLast · (1 − IsPadding) = 0`, degree 2), which removes
    the all-real cyclic trace, every row one word at one sort key with no
    group start (gate `word_ledger_gate::an_all_real_ledger_is_refused`,
    its control that every other constraint holds on it). Its register
    ledger and program memory are 46's.

  Keeping a byte-ledger format for segments: the word ledger's `IsLast`
  on `MemoryChip` (one preprocessed column and one degree-3 constraint)
  would be a new segment format with its leaf, folds, wrap and pins for
  no soundness gain, so it waits for the next segment format as
  hardening.
- **Segment proving levers** (`proving.md` §9): the 36 cubic gates
  rewritten, narrow BLAKE2b chips, a lighter page boundary or one memory
  argument across segments, and folding device proofs (the recursion
  verifying masked proofs).
- **The cross-space credential:** a credential proven to another space or
  venue (the Poseidon2 root kind, Kreivo's `Credential` handler).
- **The signature chips:** SHA-256 and SHA-512, the bignum chip, and the
  P-256 and Ed25519 drivers, so a device can prove over a hardware key's
  signature instead of a device-held secret.
- **A device format with a heavier interaction PoW:** format 46's is 8
  bits, so well-formed junk ground for 2^8 nonces passes ingress's
  pre-check and costs a decode and the composition (11–27 ms on one x86
  thread) before its 16-bit PoW refuses it; 16 or more bits would refuse
  such junk in about 0.02 ms, at the prover's grind's cost on the phone.
- **A quiet re-measure of the device exit `0x402`'s cost** on an idle
  machine (`POSEIDON2_GAS`' 1,800 TSC cycles a native compression is an
  estimate from loaded runs); owed since plan 8.10, whose machine stayed
  loaded.
- **Segment AIR parts not yet under a forgery gate:** the program memory's
  decode binding, the jump table, the lookup tables, the memory page and
  Merkle chips, the witness-input chip, the boundary-binding argument, and
  the segment cut and closing-flag rule (`pvm/proof/SECURITY.md`).
- **Completeness limits:** an invalid dynamic jump cannot be proved; the
  ledgers cannot prove a gap of 2^27 steps between two accesses to one key;
  a BLAKE2b pointer within 256 bytes of 2^32 cannot be proved.
- **Live fault text:** `ExitReason`'s `Debug` and executor panic messages
  can carry state into logs; the fix is the variant alone and a static
  panic message with its place, checked by one audited run of a faulting
  kernel.
- **The Stwo fork's divergence citation** behind format 39 needs a
  cryptographer's review; if it falls, the masked wrap takes a new number.
- **The Blake2b host hook** (`0x400`, Kreivo's `blake2_256`) for the final
  verifier, deferred until a venue's compute weight binds.
- **The external audit's scope:** the device shape, the stock kernels, the
  Poseidon2 chip and their masking, with the recursion AIR, the final
  verifier, `derive` and the security tool's counts. Engage before any
  value rides on VOS.

## Identity and privacy

- **The identity agent replicated on every node** (`identity-and-authority.md`
  §6), and with it the per-call identity read; the replica's shape (a
  non-voting vos-raft role, or the applied state shipped to non-members as
  a read-only follower) is decided when it is built.
- **The non-repudiation side store:** a space that wants evidence keeps the
  proofs an ingress verified. Not built; ingress logs the proven origin
  only.
- **Tree syncing, its last clients:** the device library keeps each
  credential tree whole from its feed (`light-node.md` §6.7), so no query
  names the member and its proofs are against the newest root it read;
  s4's `vos.credential` facility reads it too. The actor's `path(member)`
  has no client; it goes at the credential actor's next re-pin, as
  removing it moves the actor's ELF. The feed is kept whole on the actor
  and on every device, about 77 bytes a write: a compaction (a snapshot of the leaves, then the changes since)
  is later work, should a space's history outgrow it.
- **Full privacy** (`identity-and-authority.md` §8): personal spaces, the
  shared pool, the relay layer and the holder-side prover, postponed; where
  the shared pool first runs (a JAM agent or a proving space run by the
  root space) is decided when it is taken up.
- **Authenticators and attestations:** authenticators beyond ed25519 at
  ingress (SSH keys, P-256, hardware tokens) and device-signed sessions;
  grants, delegation and narrowed authority sets with revocation epochs;
  the `Identity` origin; rate limiting keyed by origin kind
  (`identity-and-authority.md` §5).
- **Credentials across spaces:** membership and solvency proven to another
  space or to JAM, then reputation, and opt-in linking (`identity-and-authority.md` §7).
- **Secret sources:** sources that span devices, iOS, and recovery across
  devices.
- **Node-signed roots,** so a gateway cannot mark the root a proof names
  (`node/SECURITY.md`).
- **The credential facility's gaps** (`identity-and-authority.md` §7):
  forgetting an enrollment, the claim order.
- **The registry and the root space** (`identity-and-authority.md` §12): the registry agent on JAM, the
  root space under a charter, the handover triggers' numbers, and the rules
  for exit and disputes.

## Chains and extensions

- **Anchoring limits** (`proving.md` §7): a single founding key can squat a
  space's registration at a venue, and one genesis can be registered at two
  venues.

- **The Kreivo leg:** the spaces pallet (`spaces-pallet.md`) is the
  teammate's port; VOS's Kreivo client runs against the mock until the
  pallet and its transport exist. The pallet's own open questions are in
  `spaces-pallet.md` §13.
- **The extension host.** Chain transports (Kreivo over sube, a JAM light
  node) become extensions once the host is defined; the prover stays built
  into the node.

## The Clerk across spaces

- The plan is `clerk-across-spaces.md` [proposed]: the transport between
  spaces, the `ClerkSettle` handler and cipher-clerk's one-cut window.

## The core model's unbuilt parts

- **The merge lane** (`core-model.md` §9.4): built on devices (the light
  node's local actors: `crdt::{GSet, Set, Map}` stored per author, read
  filtered by equivocations and the cutoffs a host gives, `#[msg(merge)]`
  handlers run on every device that applies their operation). Open: the
  merge lane on nodes (plaintext scopes, commands reading merge fields,
  the Linear-emitted chain), the authorization rule's epochs and cutoffs
  on a log, an add-wins set and a list type, masking, and thin clients.
- **Refine on any replica,** with read-set validation (§7.2).
- **Attestable writes** ("the root after", §9.2, §11.1).
- **Upgrades:** state migration for actors.
- **Workflows:** external signals beyond replies and timers.
- **Packages:** licensing, metering per instance, bytecode visibility
  (§6.4).
- **JAM agents:** messages between agents on JAM, the per-space aggregate
  agent, and the `Jam { service }` origin with a JAM light client (§12).
- **The precompile block** `0x400..=0x4ff` reserved through a JIP (§11.2).

## Repository

- **s4's VOS pin:** s4's app pins a VOS revision whose device format is
  retired, so its device sign-in is refused until the pin moves.

- **Kreivo's retired indices:** the spaces pallet's calls, events, errors
  and statuses keep their holes (`spaces-pallet.md`) until the pallet's
  port compacts them and regenerates the conformance vectors.
