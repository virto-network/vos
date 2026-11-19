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
  connections (`[onion] ssh_connections`, 128 by default, each given 30 s
  to authenticate) have no idle close (russh's inactivity timeout is reset
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
  `Personal`'s `acknowledge` and `acknowledgements` stay for them.
- **Restore elsewhere and the move's carry** [deferred, dated 2026-11-17;
  `light-node.md` §3.9]: a restore lands at its own home (then moves),
  and a move carries nothing, valid only while the personal space holds
  the credential and device books; a third local actor whose rows no
  device writes again (the wallet) needs the carry first.
- **The registry and the root space** (`identity-and-authority.md` §12): the registry agent on JAM, the
  root space under a charter, the handover triggers' numbers, and the rules
  for exit and disputes.

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
