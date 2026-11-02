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
- **The executors' verification bound** on a many-core host: the per-core
  verification table is measured on the development machine only; a bound
  per verification under full load (within 5 ms on average) is not yet a
  gate.

## Proving

- **The device prover's next levers:** a per-program CPU (the CPU's
  columns cut to the opcodes a kernel uses) and word-level memory. The
  4-way CPU split by opcode family is not built.
- **Segment proving levers** (`proving.md` §9): the 36 cubic gates
  rewritten, narrow BLAKE2b chips, a lighter page boundary or one memory
  argument across segments, and folding device proofs (the recursion
  verifying masked proofs).
- **The cross-space credential:** a credential proven to another space or
  venue (the Poseidon2 root kind, Kreivo's `Credential` handler).
- **The signature chips:** SHA-256 and SHA-512, the bignum chip, and the
  P-256 and Ed25519 drivers, so a device can prove over a hardware key's
  signature instead of a device-held secret.
- **The binding sweep's budget** (a consensus rule in refine) is not bounded
  separately.
- **A quiet re-measure of the device exit `0x402`'s cost** on an idle
  machine.
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
- **The external audit's scope:** the credential AIR, the device shape, the
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
- **Tree syncing:** members fetch their credential tree's paths from a node,
  which learns which leaf a member asks for (the path leak), and the logged
  `map_root` is a fingerprint that links a member's requests across scopes.
  Both are stated in `node/SECURITY.md`; the fix is a synced tree a member
  holds.
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

- **The merge lane** (`core-model.md` §9.4): incremental apply per scope,
  author chains, storage-backed CRDT types, masking and read-time
  filtering per type, and devices running merge handlers locally.
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

- **Reproducible path-dependent blobs:** the default agent's ELF and the two
  Wasm blobs hash by their checkout path, so they stay out of `blobs.lock`.
  `trim-paths` does not fix them (out-of-root path dependencies hash by
  absolute path and reorder `.text`); a fixed build path does.
- **Version counters and retired indices** reset before the first release,
  in one re-pin of program ids and fixtures.
