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
    table. Padding inside both ledgers is harmless (gates
    `memory_ledger_padding_gate::padding_between_the_ledgers_real_rows_is_harmless`
    and `register_ledger_gate::padding_between_the_ledgers_real_rows_is_harmless`).
    32 and 39 prove the recursion AIR, which has no memory argument.
  - **Device 46:** retired and deleted; its number is never reused. Its
    byte ledger let a byte have two boundary rows, so a read could see a
    byte's first touch instead of its last write.
  - **Device 47 (the word ledger):** consistent. `IsLast` keeps padding
    past the real rows, one sorted run, a word one group; a second
    boundary row's `ts = 0` write has no start to consume it (gates
    `padding_between_real_rows_is_refused`,
    `a_word_touched_twice_at_the_boundary_is_refused`); and the last row
    is padding (`IsLast · (1 − IsPadding) = 0`, degree 2), which removes
    the all-real cyclic trace, every row one word at one sort key with no
    group start (gate `word_ledger_gate::an_all_real_ledger_is_refused`,
    its control that every other constraint holds on it). Its register
    ledger (`DeviceBoundaryChip`'s preprocessed registers, entry at
    timestamp 1) and program memory (preprocessed, read-only) are
    consistent.

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
- **A device format with a heavier interaction PoW:** format 47's is 8
  bits, so well-formed junk ground for 2^8 nonces passes ingress's
  pre-check and costs a decode and the composition (11–27 ms on one x86
  thread) before its 16-bit PoW refuses it; 16 or more bits would refuse
  such junk in about 0.02 ms, at the prover's grind's cost on the phone.
- **`0x402`'s price against its quiet cost:** one native Poseidon2-M31
  compression (`vos_pvm::precompile::poseidon2_compress`) takes 1,925 TSC
  cycles at the median, one BLAKE2b compression 405–414, ×4.65–4.75, on
  one pinned core of an idle machine (load average 0.5), three runs of 31
  rounds of 20,000 [measured, x86 dev machine (Intel Core Ultra 7 155H),
  2026-11-12; a spike outside the tree]. At BLAKE2b's gas a cycle it would
  be about 2,800; `POSEIDON2_GAS` is 3,000, the round price above it with
  headroom [decided].
- **Segment AIR parts not yet under a forgery gate:** the program memory's
  decode binding, the jump table, the Merkle chip, the boundary-binding
  argument, and the segment cut and closing-flag rule
  (`pvm/proof/SECURITY.md`).
- **Completeness limits:** an invalid dynamic jump cannot be proved; a
  run past 2^27 − 1 steps is refused before proving (`MAX_RUN_STEPS`):
  every segment's ledgers order from its `ts = 0` writes to its closing
  reads, so the bound is on the run's length, not on a gap between two
  accesses; a BLAKE2b pointer within 256 bytes of 2^32 cannot be proved.
  The 2^27 bound is also a soundness bound: the ledgers compare timestamps
  mod p, and the per-segment `ts = 0` anchor bounds every access within
  2^27, so no provable segment reaches the alias 2^30 steps away
  (`pvm/proof/SECURITY.md`, "The leaf's binding"). Lifting it takes a
  wider ordering delta or a per-segment timestamp rebase, a new format.
- **A window's page multiproof is computed from the whole memory image:**
  planning a kernel's run hashes each window's pages and the tree above
  them anew, so its host work is the windows times the image, quadratic
  in a run that touches many pages. The windows are counted against the
  segments the run's gas buys before any multiproof (`plan_kernel`), which
  bounds it; a leaf-hash cache threaded through the segment cursor would
  make it linear.
- **A device proof's interaction nonce binds the transcript before it,
  not the body after:** a replayed proof's head with another body passes
  the verifier's precheck and costs one full verification to refuse.
  Binding the nonce to the body needs a new device format.
- **The witness stream's framing:** the AIR binds each witness-input call
  alone (a count at most its capacity, its writes), so a proved run may
  be given a short or empty read and more bytes later; a constraint
  across calls (a zero read final) needs a new segment format. Until
  then a kernel frames its input by content (`pvm/proof/SECURITY.md`,
  "Three boundaries"). Every derived kernel reads its input through
  `derive`'s prologue, which reads on through short reads, ends at a zero
  read and traps past its room, then calls the entry on the bytes read;
  every entry `#[messages]` generates decodes those bytes by content (the
  message's encoding, an in-place argument's size, `served`'s rows decoded
  whole) and traps on a frame cut short, so a proved run's result is the
  live run's on the bytes it read, however they were split [audited,
  2026-11-18: the window, balance and predicate kernels, the credential
  actor's `auth` and `owner`, the test actors' device kernels; none reads
  the witness otherwise].
- **Live fault text:** `ExitReason`'s `Debug` and executor panic messages
  can carry state into logs; the fix is the variant alone and a static
  panic message with its place, checked by one audited run of a faulting
  kernel.
- **The Stwo fork's divergence citation** behind the affine DEEP batching
  of formats 39 and 47 needs a cryptographer's review; format 39's floor
  holds without it (65.33 proven bits, the least term, batched by
  powers).
- **The Blake2b host hook** (`0x400`, Kreivo's `blake2_256`) for the final
  verifier, deferred until a venue's compute weight binds.
- **The segment format's `component_mask`:** format 41's header mixes no
  mask (`pvm/proof/SECURITY.md`'s segment trust boundary); a kernel's
  verifier pins the class, and a chip dropped or added only restricts.
  Mix the mask into the transcript at the next segment format.
- **The statements service's balance:** a registration costs its sender
  core time alone, with no deposit as Kreivo takes, and every item writes
  an outcome and a queue row kept a day while spaces and evidence are
  never dropped, so anyone who buys core time can walk the service to its
  threshold, after which every item's accumulate reverts until the
  operator funds it. What a registration costs the service in bytes is
  unmeasured.
- **The jump-table gate:** the pin and `derive` refuse a program whose
  jump-table entry, static jump or branch lands on no basic-block start
  (`vos_pvm::interpreter::bad_transfer`); no forgery gate yet shows what
  the AIR alone accepts there (a CPU row continuing at the halt address
  through the table), which needs a forged multi-chip trace the gates'
  helpers do not build.
- **The prover's restructures, measured first:** the recursion's circuit
  rebuilt and its constant preprocessed tree committed again for every
  leaf, fold and wrap (`Committed` as the device path keeps it); its trace
  and interaction generation serial and scalar with an allocation a row;
  a statement's segments, leaves and each level's folds proved one after
  another on a global pool of at most 10 threads (an explicit pool and a
  memory-bounded parallel map, in the API); the widest segment chips
  filled one after another on one thread; a class found not to fit by
  generating every chip's trace; the segment cursor cloning the memory
  image for each class attempt. Each changes no proof byte.
- **The verifier's DEEP inner loop** recomputes a per-batch constant for
  every value at every query, in the fork's `accumulate_row_quotients`:
  hoisting it changes no proof or transcript, but it is a divergence on
  the verify path of the fork, for its review and a new pin.
- **One BLAKE2b compression:** the runtime, the precompiles and the
  segment chips' software path each write it, the IV a fourth time;
  exporting the precompiles' one moves the guests' panic locations, so
  every agent program id: at the next re-pin of the node's programs.
- **The runtime's inline tests** (`recompiler/mod.rs`, `refine.rs`,
  `interpreter/mod.rs`, `interpreter/memory.rs`, `gas_cost.rs`) move to
  sibling `tests.rs` files, as the crate's other modules have them.
- **Renames that move blobs:** `final-verifier/src/masked.rs` (format
  39's decode and parameters) beside `masking.rs` (the masked verifier),
  at the next change of the final verifier's circuit.
- **An AUIPC fused with its JALR** (the `call` and `tail` idioms)
  leaves the AUIPC's register unwritten where RISC-V writes it: the
  idiom's scratch (`ra`, `t1`), which compiled code does not read after
  the jump; writing it costs an instruction per tail call.
- **Docs of guest-linked crates:** `vos-abi`'s credentials functions that
  panic on values their callers validate, and `vos-pvm-codec`'s bound of
  a decoded `Vec` by items, not bytes: one line each, at the next re-pin
  of the node's programs.
- **The Blake2s-M31 channel's draws, in the fork:** made uniform (by
  rejection, as the Blake2b channel draws; 0 and 1 are 1.5 times as
  likely per coordinate today) and its doc corrected; a change of 47's
  transcript, so a new device format (`pvm/proof/SECURITY.md`, "Stwo's
  verify path, audited").
- **The lifted Merkle verifier's height-0 tree, in the fork:** its `Ok`
  moved after the shape check; unreachable here, every tree's height
  VOS's own.
- **The fork's PCS caller duties:** `verify_values` taking the DEEP
  coefficient count and the batching mode from its configuration, the
  mode mixed, rather than from the samples alone; VOS's shape check and
  header give both today.
- **Stwo's `hashbrown` requirement** is open (`>=0.15.2`), so a
  workspace whose graph holds a newer `hashbrown` re-resolves Stwo onto
  it: the fuzz targets run Stwo on `hashbrown 0.17.1` (`foldhash 0.2`)
  where the root, the kit and the Wasm blob run it on `0.15.5`
  (`tools/gates/locks.py`'s `DRIFT` names the edge). Bounding the
  requirement in the fork closes it, at its next pin.
- **The interpreter's two loops** share skip and the division, remainder
  and upper-multiply results (`interpreter/alu.rs`); the other register
  results (shifts, rotates, 32-bit arithmetic, the immediate forms,
  comparisons and bit counts) are spelled out in `step` and in the
  predecoded loop, each over its own operand decoding.
- **The kit's lock:** shipping the lock VOS's `check-kit` builds on beside
  the kit, with a command listing every package of the verify graph a
  consumer resolves at another version; and signed release tags with a
  bootstrap that verifies them (without them push access to VOS is the
  trust root).
- **A release-profile proving bench in `pvm/`** (`prove_final` over the
  Poseidon2-M31 kernel, a device prove and verify), so the timings the
  docs quote from the test profile have a reproducible twin.
- **Kreivo's `MaxProofLen`** (`spaces-pallet.md`, the reference mock and
  its vectors) suggests 262,144 bytes where the final verifier refuses
  past `MAX_PROOF_BYTES`, 143,360: a weight charged by the pallet's bound
  pays for bytes no decode accepts. Lower it with the mock and its vectors.
- **The prover's entry points under `pvm/`:** `Program::from_kernel` has
  no caller there (the node side's device install is it), and no test
  holds `tree::prove_run`'s root to a hand-built tree at `cut_class`'s
  cut.
- **Fuzz seeds:** `prove_verify_roundtrip`'s replay seeded from the ISA
  tests' programs (an encoder of its `arbitrary` input), and a halting
  program in `program_blob`'s, so both backends are compared on a
  completed run, not only on refusals and panics.
- **The masking's two missing gates:** a small chip's column committed off
  its period, which the lifted protocol's size binding (the periodicity
  value) must refuse, needs a seam in the masked prover's commit
  (`pvm/proof/recair/src/masked/commit.rs`) that commits a column at another
  size than its component's; and a known-witness leakage gate with a
  positive control (a prover whose revealed rows exceed `h`, so a
  witness-fixed linear combination of a column's revealed values cancels
  its mask, which the gate must detect where the per-value tests cannot).
- **The NEON Poseidon2 permutation** (`pvm/proof/poseidon2/src/packed/neon.rs`)
  is held to the scalar reference only by an aarch64 build's tests, and no
  aarch64 host runs the suites: a test leg on one.
- **The external audit's scope:** the device shape, the stock kernels, the
  Poseidon2 chip and their masking, with the recursion AIR, the final
  verifier, `derive` and the security tool's counts; the personal agent's
  protocol and `vos-mls`'s use of MLS (`light-node.md` §3). Engage before any
  value rides on VOS.

## Identity and privacy

- **The identity agent replicated on every node** (`identity-and-authority.md`
  §6), and with it the per-call identity read; the replica's shape (a
  non-voting vos-raft role, or the applied state shipped to non-members as
  a read-only follower) is decided when it is built.
- **The non-repudiation side store:** a space that wants evidence keeps the
  proofs an ingress verified. Not built; ingress logs the proven origin
  only.
- **Ingress without the prover:** a node computes each device release's
  program from its kernel and reference run
  (`vos_pvm_device::Program::from_kernel`), the installing node at the
  install and every other replica at its first proof, so `vos-node` links
  the device crate's prover. The verify-only build
  (`Verifier::of_release`, `just check-device-verifier`) takes the
  program's CPU words and preprocessed root as a prover build computed
  them; it needs them carried with the install (the installing node's,
  under the operator's signature, as its derivation is), a home for them
  in each replica's state, and the guard's release held to the artifact's
  kernel. Until then the plain node keeps the prover's dependency edge.
- **Tree syncing, its last clients:** the device library keeps each
  credential tree whole from its feed (`light-node.md` §6.7), so no query
  names the member and its proofs are against the newest root it read;
  the `vos.credential` facility reads it too. The actor's `path(member)`
  has no client; it goes at the credential actor's next re-pin, as
  removing it moves the actor's ELF. The feed is kept whole on the actor
  and on every device, about 77 bytes a write: a compaction (a snapshot of the leaves, then the changes since)
  is later work, should a space's history outgrow it.
- **Full privacy** (`identity-and-authority.md` §8 points here): a shielded pool
  shared by many spaces, whose integrity does not trust any one space's
  operators (it verifies each spend's proof in its guest), postponed;
  where it first runs (a JAM agent or a proving space run by the root
  space) is decided when it is taken up. A space's own pool is P2's
  (below). Its design so far: on JAM a final proof costs about 80M gas of
  refine (the JAM statements service's, measured), so about 60 fit a work
  package's 5e9, and scanning notes held on JAM needs the JAM light client
  on the device; an anonymous input travels the client path without a
  session (self-authenticating, deduplicated by its nullifier, no
  acknowledgement, a fee note inside its proof, a few padded sizes,
  accepted from any relay); notes are discovered by scanning with a
  one-byte view tag, the sender's direct delivery through the messenger
  the fast path, detection keys deferred, and with every key derived from
  one master secret a rescan of the pool doubles as recovery.
- **Authenticators and attestations:** authenticators beyond ed25519 at
  ingress (SSH keys, P-256, hardware tokens) and device-signed sessions;
  grants, delegation and narrowed authority sets with revocation epochs;
  the `Identity` origin; rate limiting keyed by origin kind
  (`identity-and-authority.md` §5).
- **Credentials across spaces:** membership and solvency proven to another
  space or to JAM, then reputation, and opt-in linking (`identity-and-authority.md` §7).
- **Secret sources:** sources that span devices, iOS, and recovery across
  devices.
- **Node-signed feed heads** (next, not built): a node's signature over the
  credential tree feed's head (its newest root, the feed's length and the
  node's time), relayed by the gateway and checked by the keeper, so a
  gateway can no longer end a device's feed answers early at a root of its
  choosing. Until then the root's grace (`ROOT_GRACE_MS`, 90 s,
  `light-node.md` §6.7) bounds such a mark to that long; binding the head
  into the proven statement was weighed and left out, as the proof
  already names its root. The same signatures would let an alarm be
  shown to a third party (`node/SECURITY.md`).
- **The credential facility's gaps** (`identity-and-authority.md` §7):
  forgetting an enrollment, the claim order.
- **The onion's screens, their last limits** (`light-node.md` §6.1,
  `node/SECURITY.md`, "The onion"): a session of the onion's screens has at
  most four host-service calls in flight, which bounds one circuit's by its
  connections and sessions, but s4's host-service requests name no peer,
  so no rate a circuit holds them to; and the onion's SSH server's
  connections (`[onion] ssh_connections`, `docs/operations.md`) have no
  idle close (russh's inactivity timeout is reset
  by the keepalives a live client answers, so an idle close needs
  s4-server to count a connection's channels and close one holding none
  for a while). Both need s4-server's work.
- **The onion's proven calls under many circuits** [known limit, dated
  2026-11-18]: a proven call's header takes its circuit's places first and
  one call a circuit waits for the onion's, so a member waits about
  C × 5 / 16 s behind C circuits holding headers alone; inside the 60 s a
  call waits up to about 190 circuits, not at the 1,024-circuit cap. Past
  that the bound is the introduction points' rate and arti's service-side
  proof of work (`pow`, behind `tor-pow`, which no arti release has
  declared ready).
- **The admin key's attestation** [known limit, dated 2026-11-18,
  `light-node.md` §3.5]: a device's admin class and its hardware and
  verified-boot flags are its own report (the keystore's `KeyInfo`), not
  an attestation chain another device verified: a modified client can
  claim a strong admin. Generating the key under an attestation challenge
  bound to the agent and the device, and each device checking the chain
  (its security level, the authentication it requires, the root of trust's
  verified-boot state), is later work; so is the PIN-authenticated delayed
  admin of a phone without a Class 3 biometric, which today cannot make
  its admin key at all.
- **A delayed admin's pairing** [not built]: its add is an operation that
  waits the operation delay (72 h) past any pairing slot's life, and a
  joiner that waits that long across restarts is not built: a delayed
  admin opens no pairing (`Error::DelayedAdmin`), and a strong admin's
  device pairs it. A phone whose devices are all delayed admins cannot
  add another.
- **A carried session's terminal geometry** [low, not fixed]: s4 sends a
  carried session's exact columns, rows and pixel size, constant per phone
  and rare in a small space, so a gateway may join a member's carried
  sessions by them, and their sign-ins across scopes. Rounding them to a
  few buckets on carried sessions, and reviewing what s4's hello volunteers
  (fonts, theme, capabilities) for the same, is s4's work.
- **The kit's calls on a phone** [built 2026-11-18, phone run pending]:
  `remove_by_kit`, `resolve_by_kit` and `kit_view` from any install, the
  restore screen's "A lost phone answers the restore"; driven on two
  phones in the PG3′ session, not yet.
- **The previous release's artifacts** [proposed]: the app ships its own
  release's stock artifacts only, so an app one release ahead of a space
  is refused at the window ("the app or the space must update") until the
  space moves; shipping the previous release's beside them needs a
  release process that keeps the previous one's ELF.
- **A cosign or a resolution whose evidence never comes** [known limit,
  dated 2026-11-18]: the operation it decides takes effect at the call,
  while the devices take it only with the call's evidence; the device
  that made it posts it until the log holds it (as every admin call's),
  so only that device lost between the call and its evidence leaves the
  devices without it, refusing the maturity (`Unsigned`) the agent
  applied. Deciding at the evidence instead moves the agent's rules.
- **An operation without its evidence is not shown** [known limit, dated
  2026-11-18]: the chrome lists verified operations only, so one whose
  evidence has not come (its device lost after the call) shows nothing
  until the agent cancels it at its due time; showing it as unverified
  needs its own notice kind and words.
- **The joiner's check is shown, not compared by the app** [known limit,
  dated 2026-11-18]: the opener's user confirms the two screens show the
  same six digits; a user who confirms without looking pairs whoever
  answered the QR first, as before the check.
- **A cosign or resolution before the evidence is refused, not queued**
  [known limit, dated 2026-11-18]: the agent refuses one that would make an
  operation without its evidence mature (`Unevidenced`), and the device
  shows the refusal; the user signs again once the operation's author has
  posted it (its next pass). Holding the second signature until then needs
  a held call of its own kind.
- **Every personal agent lapses at month 13** [risk, dated 2026-11-17,
  the owner's choice]: the yearly re-proof flow and the joiners' open
  claim (`light-node.md`'s E28) are deferred to the next stage of work, so
  no device proves `Homes.renew`, and a
  joiner holds no leaf at a home-only home to prove it with. Each agent's
  lease runs out 13 months after its claim and it enters its 180 days'
  grace (pushes refused; reads and a restore still served) unless
  that work ships both before then or the home sets a longer lease
  (`Policy::lease_ms`, 395 days by default). `Homes.renew`, `Personal.renew`, the
  recorded nullifiers, the lease and the grace stay built.
- **The MLS leaf's year** [risk, dated 2026-11-17]: a leaf
  made from a key package lives 365 days (mls-rs's lifetime), and a
  joiner's Welcome refuses a tree holding a leaf past it. The yearly
  prompt that renewed it is deferred with the re-proof; until then
  any commit of a device renews its own leaf ("Commit now" makes one), so
  a device that commits nothing for a year blocks the next pairing until
  it commits or is removed.
- **No notice of a lapsed lease** [risk, dated 2026-11-17]:
  the notice that raised the yearly re-proof also raised a lapsed lease,
  and went with it; a lapsed agent's pushes are refused (`Lapsed`) with
  no notice of its own. The deferred re-proof flow brings both back.
- **A left personal space's admin key** [known limit, dated 2026-11-17]:
  a leave (a move, a pairing from another space) drops the light node's
  store and keys but leaves the admin key in the UI's keystore, where it
  could still sign at the old agent, at which the device stays listed
  until its other devices remove it. Deleting it needs a prompts call of
  its own.
- **Scope checkpoints** [deferred, dated 2026-11-17;
  `light-node.md` §3.6, §8 C4; `node/light/SECURITY.md`]: a newly paired
  or restored device reads each scope from its start and has read no
  position to hold the operators to, so it can be served a shortened
  scope (its newest envelopes withheld) without an alarm; `Partition`
  is raised only once a later envelope's `seen` position crosses the cut.
  `Personal`'s `acknowledge` and `acknowledgements` stay for them. Their
  design: a checkpoint is a scope's state after every envelope up to a
  position `P` whose causal past is complete, so every device that has
  read to `P` computes the same state (two devices checkpointing at once
  hold the same state); its author pushes it sealed with `P` and the
  state's hash inside. A new device trusts the checkpoint of the device it
  pairs from, which already hands it the archive and `R` and sends the
  checkpoint's hash over the pairing channel; a restore, with no pairing
  device, trusts a checkpoint that two devices other than its author
  acknowledged (each having recomputed it), or replays. So a new device
  never replays years of history, and holds the operators to the
  checkpoint's position.
- **Restore elsewhere and the move's carry** [deferred, dated 2026-11-17;
  `light-node.md` §3.9]: a restore lands at its own home (then moves),
  and a move carries nothing, valid only while the personal space holds
  the credential and device books; a third local actor whose rows no
  device writes again (the wallet) needs the carry first.
- **The registry and the root space** (`identity-and-authority.md` §12): the registry agent on JAM, the
  root space under a charter, the handover triggers' numbers, and the rules
  for exit and disputes.

## The personal space and the light node

What `light-node.md` leaves for later; the dated risks and deferred flows
are under "Identity and privacy" above.

- **The phone gates not yet recorded as passed** (`light-node.md` §2.4):
  PG1′ and PG2′ at format 47 on the Fairphone 6, twice a day apart; PG3′'s
  flows and PG6 as onion runs on two phones with the security key; PG5's
  battery and rendezvous counts; the recorded background-job cases (the "rare"
  bucket, three days offline, a force-stop, an operation's latency to its
  notification), which the device-change windows are pinned against.
- **The personal agents' scale gate** (`light-node.md` §3.3, "The scale gate"):
  the snapshot's limit and the memory's as a fixed overhead (+56–59 KiB a
  replica) are met; the commit p99's is missed. The rerun at capped load
  (2026-11-20) found the rise real at 5,000 calls a second, where the load
  sits at the node API's stream bound (+87%, and one run collapsed), and
  +23% at 3,000, below it: the personal agents' long calls hold the
  executors the shards' batches wait for. Open: a lane for them (or a
  queue ordered by gas), then a gate run below the knee with a second
  pair for its spread (`api_in_flight` raised, or the rate lowered).
- **The control log's head in an admin call** [not built]: an admin
  call's arguments do not name the control log's head it was made
  against, so a device cannot check that an operation was signed against
  the log it was shown: a route forking the log a device reads can log
  again a removal of it once signed and vetoed, and mature it unvetoed,
  which takes the device out of its group for good (`light-node.md`
  §3.6, "never on a refusal"). Binding an operation's batch time to its
  call's session (`t0` to `t0` plus the session's life) would narrow the
  replay to the calls of the last session's life.
- **Messaging between members** on `vos-mls` [E12], in a space or across
  spaces, the personal agent's inbox its door (`light-node.md` §3.7,
  §3.10). MLS virtual clients share a virtual leaf's signature and HPKE
  keys across the user's devices, a secret that syncs, against E2's
  letter: the owner is asked first.
- **Plaintext Merge scopes on nodes** ("The core model's unbuilt parts",
  below) and actors the user installs in the personal agent (E9).
- **Several homes:** a second home mirroring the first, a live handover
  between homes, and a successor group after a lost home (`light-node.md`
  §3.9); reaping a lapsed agent after its grace and returning it to the
  pool, with tenancy numbers (§3.3).
- **Forwarding between nodes,** for a gateway that lists only some of a
  home's nodes (`light-node.md` §3.3; today a home's gateways list every
  node).
- **Person leaves for `once` scopes:** a member with three devices holds
  three leaves, so a `once` scope admits it three times (`light-node.md`
  §3.8, `identity-and-authority.md` §5).
- **History and storage:** history horizons for the key archive, garbage
  collection of covered envelopes and of earlier epochs' archives, and a
  blob store for media behind the blob-ready `push` and `since`
  (`light-node.md` §3.4, §3.6); pipelined `since` reads, and re-reading an
  envelope passed over once a later archive opens it.
- **An encrypted export file** under the kit's key [E16].
- **Pluggable transports** (obfs4 through lyrebird, Snowflake, WebTunnel)
  beside the plain bridges [E22]; **SSH over QUIC**, or a roaming
  transport in the manner of mosh, once UDP over Tor exists [E23].
- **Excising a device's operations** after the fact (`light-node.md` §8,
  C1); today the remedy is removing the device.
- **A consent model per program id** for developers' device kernels over
  private data (`light-node.md` §4.4); today such a kernel takes only what
  the user hands it, never keys.
- **Local workflows with device effects** (`ctx.prove`,
  `ctx.call_remote`), which would move the light node's glue around a
  proven call into the actor.
- **A device too small for a full replica,** and a wallet's mirror of a
  large pool (`light-node.md` §8, C10).
- **MLS on the device is new code:** confirmed epochs, admin-signed
  commits and copy-and-swap over mls-rs (`light-node.md` §3.4), the risk
  the external audit's scope names.
- **Node-signed answers,** so a device's alarm becomes proof a third
  party can check (`light-node.md` §8, B4; "Node-signed feed heads",
  above, for the tree's feed).
- **Not in this design:** a personal space shared by more than one
  person; iOS (nothing below the secret store is Android-only, but nothing
  builds it); an anonymity network of VOS's own, or mixnets: Tor only.
- **Proof bytes over Tor:** the upload dominates a proven call's latency
  over an onion circuit (`light-node.md` §6.3); smaller device proofs and
  an upload split over several circuits are the levers.

## Private payments (P2)

Designed, not built [decided, E13, E18]. P1, the pseudonymous ledger, is
built (`light-node.md` §5). P2 hides payer, payee and amount from the
operators and every other member inside a shielded pool; deposits into
and withdrawals from the pool are visible as transparent legs. It builds
on the personal space and Tor as built.

### The shape

Two actors and one library:
- **`Payments`**, the public actor in the space, gains a shielded pool
  beside cipher-clerk's double-entry ledger (note commitments, nullifiers,
  encrypted notes). It never sees a note's value or owner.
- **`Wallet`**, a local actor in the user's personal space: the notes
  the user's devices hold and the nullifiers they have spent, each note
  marked with the device whose key spends it (E2), synced across the
  devices through the personal space.
  It plans spends; the light node builds and proves them with the
  device's key, which never enters the actor's state. A local actor whose
  rows no device writes again needs the move's carry first (above, under
  "Identity and privacy": "Restore elsewhere and the move's carry").
- **cipher-clerk**, redesigned (below): the ledger kernel, and a shielded
  module whose spend rule is one `no_std` Rust function, the same function
  the device kernel runs and the reference implementation checks.

**The spend is the showcase:** the kernel the phone proves is
`cipher_clerk::shielded::check` called from a five-line method. There is no
circuit: the rules (owner binding, nullifier derivation, membership,
Faerie Gold, value balance with 64-bit range checks as `checked_add`) are
ordinary Rust, and "the reference check is bit-identical with the
circuit" (cipher-clerk's Phase 3 entry criterion 11) holds by construction.
Its spending key reaches only kernels the light node ships
(`light-node.md` §4.4, "Which kernels see a secret").

### cipher-clerk, redesigned

cipher-clerk (codeberg's `Virto/CipherClerk`; VOS pins tag `v0.3.0`, the
merge commit `b841640`, in its root `Cargo.toml`, and uses its codec, `Account`, `Layer`,
`Value` and `settlement::window` in the `accounts` and `window` test
actors) has a sound transparent kernel (its tests are most of the 315 the
workspace runs with every feature; about 114 are the privacy modules') and a notes
prototype that is not for value (its status file says so): Pedersen commitments on
Ristretto, a BLAKE2b nullifier, a pool that rebuilds its tree on every
insert (F21), no spend proof, and a `pvm-precompile` feature that routes
scalar multiplication to a Ristretto chip VOS removed as unsound
(`core-model.md` §11.2), pinned by a git dependency on VOS at
`9f5337fb`. Its own Phase 3 entry criteria (its viability plan)
name what a private tier must settle; this design answers them.

**What changes, released as v0.4.0 (breaking) with P2, from cipher-clerk's own
repository** [decided, E18]**:**

| # | change | why | Phase 3 item |
|---|---|---|---|
| R1 | **One hash, Poseidon2-M31's compression `C`**, behind a trait `Compress { fn compress(l: &Digest, r: &Digest) -> Digest }`; cipher-clerk ships no permutation; VOS's SDK implements it over `0x402` in a kernel and natively on hosts; cipher-clerk's tests take golden vectors from VOS | the zkVM proves `0x402` in one chip row and BLAKE2b or a curve not at all cheaply; one hash keeps device shapes free of BLAKE2b (`proving.md` §8, `H_io`) | 8 |
| R2 | **Hash commitments, not Pedersen**: `cm = C(C(T(note), [asset, v₀, v₁, v₂, 0…]), C(rho, C(owner, r)))`, value in three 24-bit words; `r` a 248-bit blinding the caller passes (randomness as a parameter, v0.3.0's rule kept). The order lets a pool compute a deposit's `cm` from a public amount, a protocol `rho` and the depositor's `C(owner, r)` (below) | the spend proof checks the balance in Rust, so no homomorphism is needed; no curve in the kernel | 4 |
| R3 | **Keys hash-only, per device**: `sk` per device and pool, 32 random bytes drawn by the light node, wrapped under a per-use keystore key; for recovery, HPKE-sealed to each kit's X25519 key (never under `R`, which every device holds) and stored at the personal agent, released only to a matured restore as `R2` is (`light-node.md` §3.5), re-sealed at each kit rotation: no device opens another's `sk`, a leaked kit alone gets nothing before 7 days unvetoed and unrefuted, and the operators with a leaked kit can spend (the owner is asked first); `owner = C(T(note-owner), sk)`, `nk = C(T(note-nf), sk)`; the device proves knowledge of `sk` | spend authorization without an embedded curve: option 1 of item 1 ("the device proves, with `ak = Poseidon(ask)`"); no delegated proving, which the light node does not need | 1, 2 |
| R4 | **Nullifier** `nf = C(nk, C(pool, cm))`, scoped to the pool's id; **`rho` of each output** `C(T(rho), C(nf₀, [i, 0…]))` (two calls), bound to the transaction's first nullifier; **a deposit's `rho`** `C(T(rho-deposit), W(b))`, `b` the deposit call's binding digest, unique and recorded | unique per note, unlinkable to `cm` without `nk`; `rho` fixed by the protocol closes Faerie Gold (F3) for spends and deposits alike; `nk`'s tag apart from the credential's `T(nf)`; a note of one pool spends in no other | 3 |
| R5 | **Fixed-shape transactions**, `Tx<const I, const O>`: `asset` (the transaction's one asset, its fee's too), `anchor`, `nullifiers: [Digest; I]`, `commitments: [Digest; O]`, `memos_hash`, `value_balance: i64` (a withdrawal's amount, or 0), `leg` (the withdrawal's destination account id, or zero), `fee: u64`, `pool: Digest`, `binding`; deposits are not transactions (below) | a proof's shape is its kernel's; two kernels, 1-in-2-out (`spend`) and 2-in-1-out (`join`), cover payments and consolidation; the transparent leg and the fee's asset are in what the proof binds | 4, 5 |
| R6 | **`shielded::check::<H, I, O>(tx, witness) -> Result<(), SpendError>`**: `no_std`, no allocation, fixed arrays, no `BTreeMap`, no panic; `Witness` the input notes, their positions and paths, `sk`, the output notes; plus `shielded::Plan` and `shielded::build` (host side, taking the device's `sk`) | the device kernel's body; the same function runs on hosts as the reference | 11 |
| R7 | **An incremental note tree**: append-only, depth 32, its frontier (33 digests) and a ring of the last 64 anchors in point rows behind a `NoteState` trait (as `LedgerState`), O(32) calls an append | F21; the actor stores it in its tables; the anchor ring mirrors the credential actor's | 7 |
| R8 | **The pool a pseudo-account of the L0 kernel**: a transaction's `value_balance` is one kernel transfer between the payer's or payee's transparent account and the `ShieldedPool` pseudo-account, under the depositor's `Authority` or the proof's | `seal` and `open` kept as the kernel's two legs, not a second ledger | 9 |
| R9 | **Encrypted notes**: a memo per output, X25519 to the recipient's address key and ChaCha20-Poly1305 (the `viewing-keys` envelope's AEAD), a one-byte view tag; outgoing ciphertext under the sender's `ovk`; host side only, never in a kernel; the transaction binds `memos_hash` | note delivery through the pool's feed (below); the recipient checks a note's `owner` against its own on receipt (F8) | 2, 6 |
| R10 | **Deleted**: `notes` (replaced by `shielded`), `pvm-precompile` and its VOS git dependency, `fmd-experimental`, `stealth-experimental` (F8: unspendable), the Ristretto `AuthKey` and Schnorr outside the `signatures` helper the CLI uses | fewer pieces; nothing in VOS uses them; the view tag and scanning replace FMD at this scale | — |
| R11 | **Recovery and refusals** written as tests against `check` and the pool: Faerie Gold, a spend back by the sender, a double spend (at the actor), an anchor out of the ring, a fee or memo-hash mismatch, an overflow, a wrong pool, a mismatched owner on receipt (the wallet's check, R9) | Phase 3's refusal list | 10, 11 |

**Kept as they are:** the L0 kernel (`apply_batch`, `Authority`,
`LedgerState`, the two layers, two-phase transfers, the encodings, the
fit check), payments between spaces and `settlement::window` (the window
test actor's kernel), and `ValueModel` (`Value` the only model; the
confidential model stays on paper: notes make it unnecessary for privacy).
cipher-clerk stays independent of VOS: its kernel depends on no VOS crate
once R10 drops the git dependency, and VOS depends on its tag.

### The code a developer writes

The whole of the payments actor's private path, with cipher-clerk doing
the cryptography (sketch; names follow the table above):

```rust
use cipher_clerk::shielded::{self, Spend, Join, NoteTree};
use vos_sdk::prelude::*;

#[actor]
pub struct Payments {
    clerk: Clerk,                       // cipher-clerk's L0 accounts, in tables
    notes: NoteTree,                    // the frontier and the anchor ring
    spent: Table<Digest, ()>,           // nullifiers
    memos: Table<u64, Memo>,            // a position's encrypted note
}

#[messages]
impl Payments {
    /// Proven on the payer's device; never run by a node.
    #[attestable(device, reference = shielded::reference::<1, 2>)]
    pub fn spend(witness: &Spend, #[public] tx: &shielded::Tx<1, 2>) {
        shielded::check::<P2, 1, 2>(tx, witness).expect("a valid spend");
    }

    #[attestable(device, reference = shielded::reference::<2, 1>)]
    pub fn join(witness: &Join, #[public] tx: &shielded::Tx<2, 1>) {
        shielded::check::<P2, 2, 1>(tx, witness).expect("a valid join");
    }

    /// A proven spend: its nullifiers once, its notes appended.
    #[msg(proven = spend)]
    pub async fn pay(&mut self, ctx: &mut Command<Self>, tx: shielded::Tx<1, 2>,
                     memos: [Memo; 2]) -> Result<(), PayError> {
        self.notes.accepts(&tx.anchor)?;
        tx.memos_hash.matches(&memos)?;
        for nf in tx.nullifiers { self.spent.insert_new(&nf)?; }
        for (cm, memo) in tx.commitments.into_iter().zip(memos) {
            let at = self.notes.append(cm)?;
            self.memos.insert(&at, &memo);
        }
        self.clerk.pool_leg(ctx, tx.value_balance, tx.fee)
    }

    /// A note from a transparent account, under its owner's proof. The pool
    /// computes the commitment itself from the public amount, a `rho` the
    /// call's binding fixes, and the depositor's hidden `C(owner, r)`: a
    /// deposit cannot mint more than it debits, and no two share a `rho`.
    #[msg(credential = Owner)]
    pub async fn deposit(&mut self, ctx: &mut Command<Self>, from: AccountId,
                         hidden: Digest, memo: Memo, amount: u64) -> Result<(), PayError> {
        let rho = shielded::deposit_rho::<P2>(ctx.binding());
        let cm = shielded::commit::<P2>(self.asset(), amount, &rho, &hidden);
        self.clerk.debit_into_pool(ctx, from, amount)?;   // the L0 kernel, the owner's authority
        let at = self.notes.append(cm)?;
        self.memos.insert(&at, &memo);
        Ok(())
    }

    /// The feeds a wallet scans, every wallet all of them: commitments and
    /// memos from a position on, and nullifiers from a position on (never
    /// a query for one nullifier, which would tell the operators which).
    #[msg]
    pub async fn notes_feed(&self, from: u64) -> Page<(Digest, Memo)> { /* … */ }
    #[msg]
    pub async fn spent_feed(&self, from: u64) -> Page<Digest> { /* … */ }
}
```

The wallet, a local actor whose scope the personal space syncs:

```rust
#[actor]
pub struct Wallet {
    notes: crdt::GSet<Owned>,           // notes received: the note, its position, its device
    spent: crdt::GSet<Digest>,          // nullifiers spent or seen spent
    tree: crdt::Map<u64, Digest>,       // the pool's leaves seen so far, for paths
}

#[messages]
impl Wallet {
    #[msg(merge)]
    pub fn received(&mut self, note: Owned) { self.notes.insert(note) }

    #[msg(merge)]
    pub fn spent(&mut self, nf: Digest) { self.spent.insert(nf) }

    #[msg]
    pub fn balance(&self) -> u64 {
        self.unspent().map(|n| n.note.value).sum()
    }

    /// The plan of a spend paying `amount` to `to` from `device`'s notes,
    /// its change back to `device`: the light node builds it with that
    /// device's key, proves it and sends it to the pool.
    #[msg]
    pub fn prepare(&self, device: Owner, to: Address, amount: u64)
                   -> Result<shielded::Plan<1, 2>, PayError> {
        let input = self.pick(device, amount)?;
        Ok(shielded::Plan::new(input, self.path(input.position), to, amount))
    }
}
```

**What the light node does around it** (a `pay` operation of the
facility, `light-node.md` §7.3): calls `prepare` on the local wallet, builds the
transaction and its witness with the device's `sk` and fresh randomness
(`shielded::build`), proves the `spend` kernel on them (its device
program computed from the light node's own build of cipher-clerk and
checked equal to the pool's installed one, `light-node.md` §4.4), sends the proven call
over Tor, and on `Ok` records `spent(nf)`. A local workflow with
device effects (`ctx.prove`, `ctx.call_remote`) would move that glue into
the actor; it is a later extension of the local host.

### What is proved on the device, and what is checked publicly

**Proved on the device** (the `spend` kernel, `shielded::check`):
- the payer knows `sk` behind the input note's `owner`;
- the input note's commitment is a leaf of the pool's tree under `anchor`
  at the witnessed position;
- each nullifier is `C(nk, C(pool, cm))` of its input (R4);
- each output's commitment is well formed, its `rho` the protocol's;
- `Σ inputs = Σ outputs + fee + value_balance`, every value and sum in
  `u64` with checked arithmetic (the 64-bit range checks);
- the proof binds the call (`binding`), the pool, the anchor, the memos'
  hash, the fee and the transparent leg.

**Checked publicly, by the space:**
- at ingress: the generic checks and the proof against the `spend`
  program (`light-node.md` §4.3); no pool-specific pre-check;
- at apply (`pay`): the anchor accepted (newest, or superseded within
  `ROOT_GRACE_MS`, the credential ring's rule, 90 s: a spend proof's
  larger upload, about 1.2 MB, still fits its 45 s margin at the median
  circuit, and P2 sets its own window if its measured trip does not); each nullifier inserted
  once (a second is refused, the whole call with it); the memos' hash;
  the commitments appended; the transparent leg applied by cipher-clerk's
  kernel (a withdrawal credits the account `leg` names from the pool's
  pseudo-account);
- at a deposit: the depositor's owner proof, the debit by cipher-clerk's
  kernel, and the commitment computed by the pool (above), so the value a
  note holds is the value debited.

**What the operators learn:** that a spend happened, when, its fee, its
transparent leg if any, and two new commitments; never the payer, the
payee, the amount or which note was spent among those under the anchor.
Over Tor (`light-node.md` §6), not the address it came from.

### What the pool trusts

- **Authority is the users':** no operator can spend a note (it needs
  `sk`), and there is no `rekey`: the private tier is non-custodial in its
  authority, unlike today's ledger (`identity-and-authority.md` §7).
- **Integrity is the operators':** a space's nodes trust each other
  (`core-model.md` §5); an operator can append a commitment no deposit
  paid for (inflation), refuse a spend, or roll back. Users see the
  pool's transparent total (the pseudo-account's balance) and their own
  notes, not a proof of supply. A pool that needs integrity without
  trusting its host is "Full privacy"'s (above), postponed.
- **The anonymity set** is the pool's notes under the anchors in use: in a
  small space, small. A member who spends right after receiving links
  the two by timing; the wallet waits a random interval before spending a
  fresh note, and joins run when the phone is idle and charging.

### The spend's cost

[est] by counting, against the auth kernel (1,722 steps, 43 calls of
`0x402` with `H_io`'s):
- calls: `owner` and `nk` 2, the input's commitment 4, its nullifier 2,
  its path 32, two outputs' `rho` 4 and commitments 8, `H_io` over a claim
  of about 260 bytes 12: about 64, under the Poseidon2 chip's 2^10 floor;
- steps: about 2,800–3,600 in SDK form, so the CPU at 2^12 rows (auth's
  2^11), the memory ledger one power of two above auth's;
- the cell model's time at that size: 0.9–1.3 s on the Fairphone 6 today
  [model, est], 0.7–0.95 s with both levers; peak 0.7–0.9 GiB; a proof of
  about 1.1–1.3 MB.
- `join` (2 in, 1 out) adds a path and a nullifier: about 100 calls,
  4,500–5,500 steps, 2^13 rows, 1.4–1.9 s today [est]; it runs in the
  background, not on a user's tap.
- **The gate** (PG4, a target until the spend's steps are
  measured): the spend at most 1.0 s at the median
  with the levers, at most 1.5 s without them.

## Execution

- **Host bounds past the Gray Paper's reader** (`vos_pvm_program`,
  `vos_pvm::backend`): a zero-width jump table holds at most as many
  entries as its blob has bytes, a refusal the reader gives as it gives
  an invalid blob's (Ψ's panic, `machine`'s HUH), for any blob, a
  service's under `W_C` among them; and a host prepares at most
  `MAX_PREPARED_CODE` (4 MiB) of code on either backend, a backend
  refusal past it, a valid program only the JAM-only host's `machine`
  call can name (a VOS host refuses an inner program past 2 MiB first,
  `inner::budget`). A table of implicit zeros (a length, no entries) and
  a fallible predecode lift both.
- **Arithmetic on a code pointer in a register** (`vos_pvm_compiler`):
  the compiler gives a code pointer its jump-table address, so `addi t0,
  t0, 4` then `jalr t0` selects another entry than the source's
  instruction four bytes on. It cannot see the arithmetic: only a
  `jalr`'s own displacement past ±1 is refused, and a source that offsets
  a code pointer otherwise runs differently.
- **The JAM-only host's inner machines** follow the Gray Paper
  (`inner::Profile::GrayPaper`): a halted or panicked machine keeps its
  funded flag, and nothing bounds the programs they prepare or the pages
  they map, at the text's `machine` and `pages` prices. VOS hosts bound
  both (`inner::budget`); the two erratum drafts (the funded flag, the
  budget) are for the text, until which a host serving untrusted refines
  runs them as a VOS host.
- **The recompiler in a confined worker process:** compiled guest code
  runs on the host's own threads, guarded in-process only (the guarded
  window, strict fault attribution, masked dynamic-jump indices, the
  start-up probe). A worker would hold the guest window, the JIT code and
  the context, the host keeping its alias of the memfd for host calls,
  and would also take the kernel's per-process mapping limit and a
  backend crash off the host. To settle: confinement must not depend on
  namespaces (rootless Podman breaks them, Docker's default profile
  denies them), so a seccomp allowlist is the boundary (PolkaVM's worker needs ten system
  calls) with namespaces and Landlock as extra layers where available;
  which machines share a worker (inner machines never with their outer
  program; pooled per-machine workers, as PolkaVM does); write tracking
  across processes (userfaultfd, which default containers deny, or the
  worker's own `mprotect` tracking, or a descriptor the host scans); each
  worker opting into indirect-branch protection with
  `prctl(PR_SET_SPECULATION_CTRL)`. `seccompiler` and `landlock` for the
  confinement; PolkaVM's zygote is the design to copy, not a dependency.
- **KVM as an optional later tier** for high-value bare-metal nodes, not
  the base (it needs `/dev/kvm`, and is no faster per host call).
- **`RecompiledPvm`,** the recompiler's test-only machine with its own
  memory path: retired once the instruction vectors run on
  `backend::StandardMachine`, the production path, on both backends.
- **A slot's activation during a native run is not counted against the
  mapping bounds:** a write that starts tracking a 4 MiB slot between two
  untracked ones splits two kernel mappings off its writable run, from
  the fault handler, and only the next permission sync counts them (and
  an idle machine's claim). On a VOS host the pages an invocation maps
  (`inner::budget`) bound the slots it can split; the JAM-only host's
  inner machines are unbounded, and a failed activation there is a
  backend error where the interpreter gives a result. Counting the splits
  atomically at activation and, past the bounds or on a failed
  `mprotect`, exiting before the store, retiring the window and finishing
  on the interpreter would close it.
- **The recompiler's preparation simulates block costs twice:**
  `compile_code` runs the gas simulator inline in its code generation,
  and the interpreter tables a native program keeps beside its code (for
  a retired window) run it again, so preparing for the recompiler costs
  twice the simulation it needs; no result depends on it. Code generation
  taking the interpreter's per-pc block costs would halve it, at the cost
  of the recompiler's own walk, which the gas tests now hold to the
  reference as a second computation.
- **Decoding bytes a kernel was given** (`vos_pvm_codec`,
  `vos_tree::verify_encoded`): memory grows with the input by a factor
  the types set (an item's size for each byte of a short encoding; about
  56 bytes a three-byte branch entry), stated where each is; a kernel
  sizes its heap or caps its input by it. A decoder held to a byte budget,
  refusing past it, would make that a refusal rather than a trap.
- **The JAM-only host's package** (`JamRefine`): `fetch` kinds 7 and 10
  serve the encoded package and context as the caller gives them; the
  fixture encodes no work package, so nothing holds them to its items.

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

- **Kreivo's retired indices:** the spaces pallet's calls, events, errors
  and statuses keep their holes (`spaces-pallet.md`) until the pallet's
  port compacts them and regenerates the conformance vectors.
- **A guard below the venue guests' stack** (`final-verify`,
  `statement-service`): their 1 MiB stack is a `.bss` array, above the
  guest's statics, so an overflow writes them rather than trapping. A
  standard program's read-write region has no holes, so the guard is a
  placement: the stack first in that region, below it the unmapped gap or
  the read-only data, where a push faults. That needs a linker script for
  the venue guests (as `pvm/guest/pvm.ld` is the agents'), which moves
  their blobs; or the Gray Paper stack with its own size, which the
  compiler ties to the read-only base today.

## Tooling

- **Toolchains and tools by hash:** `rust-toolchain.toml` pins its nightly
  by date and the kit's toolchain by version (rustup checks each by its
  own signed manifest), and the gates' tools (`cargo-deny`, `cargo-fuzz`,
  `just`, `nu`) are whatever the host installed. Neither rustup nor
  `cargo install` takes a hash of what it installs; a tools manifest (each
  tool's version and its binary's SHA-256) checked by a gate is the next
  step.
