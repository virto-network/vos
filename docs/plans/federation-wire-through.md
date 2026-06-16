# Federation wire-through: expose the segmented conservation proof end-to-end

Status: **PLAN (starting).** Branch `voucher-state-transition`. Closes the gap
between "the trustless conservation proof exists + is sound in-circuit" and "a
receiving bank actually verifies it." See `project_federation_wiring_state`
(memory) for the verified starting state.

## Starting state (verified 2026-06-15)

- **In-circuit soundness is complete.** `verify_standalone` binds all four
  boundary fields (`memory_root` via the in-AIR page-Merkle trie, pc/ts,
  registers/io-hash, ristretto `ts`). `verify_chain_standalone(proofs,
  commitment, expected_initial_root) -> final_root` exists + is tested
  (`zkpvm/tests/chain_standalone.rs`). Format v8.
- **Guest proves conservation** (`SuccinctTransitionWitness::verify_transition`),
  io-hash binds `(issuer, amount_commit, state_root_before, state_root_after)`.
- **Unwired:** the prover extension `prove`/`verify` are single-shot; the real
  transition only proves as a segment **chain**; clerk-bridge ships ONE
  `proof_hash` to the single `verify`; `VOUCHER_CHECK_COMMITMENT` is stale; the
  federation e2e uses Mode::Signature + placeholder rejects (happy path skipped).

## Data flow (target)

Issuing bank (producer, OFFLINE — prove is slow, that's fine):
1. Build `SuccinctTransitionWitness` from the real ledger snapshot + batch.
2. Trace voucher-check with the witness → full `SideNote`.
3. `prove_chain`: segment (UNIFORM size), prove each segment (`prove_mobile`),
   collect `Vec<Proof>`.
4. CAS-put a **chain blob** = `bincode(ChainProof { segments: Vec<Proof> })`;
   the voucher's `CcProof{ mode: External, bytes }` carries the 32-byte CAS
   hash of that blob (unchanged wire shape — still one hash).
5. Sign + send the voucher (libp2p; the blob is fetched on demand via the
   existing proof-blob CAS fan-out, `project_proof_blob_cas`).

Receiving bank (verifier, FAST — sub-second):
6. clerk-bridge `dispatch_external_proof` → prover ext `verify_chain` with the
   blob hash + `public_bytes` + `return_bytes=[1]` + the configured
   `program_commitment` + `peer_prefix`.
7. Extension: `blob_get` the chain blob → `verify_chain_standalone(segments,
   commitment, expected_initial_root = segments[0].initial_state.memory_root)`
   → check `segments.last().final_state` io-hash == `compute_io_hash(public,
   return)`. Return 1/0.

## Design decisions

- **Chain blob, not N hashes on the wire.** Keep the voucher's `proof.bytes` as
  a single CAS hash (no `CcProof`/cipher-clerk wire change); it addresses one
  blob holding the whole `Vec<Proof>`. One fan-out fetch. (Revisit only if blob
  size — N×~1.4MB — is a problem; then a manifest-of-hashes + per-segment fetch.)
- **`expected_initial_root` is self-anchored from the chain.** For the
  federation there is no external "expected" entering image — the entering RAM
  image embeds the per-voucher witness. The verifier passes
  `expected_initial_root = segments[0].initial_state.memory_root` (which is
  bound in-circuit to segment 0's genuine entering image). Soundness of the
  conservation statement comes from: per-segment validity + memory_root
  continuity across the chain + the io-hash binding `(roots, amount)` + the
  program commitment pinning the voucher-check code. The entering image is the
  prover's input (the witness IS prover input; the guest verifies it). **FLAG
  for adversarial review at implementation: confirm a producer cannot gain
  anything by choosing a non-canonical entering image given io-hash + commitment
  + continuity already pin the semantics.**
- **Uniform segment sizing for one commitment.** The program commitment is the
  preprocessed-trace Merkle root → log_size-dependent. All chained segments
  must share one log_size. `prove_chain` pads every segment to a fixed
  `min_log_size` (= the max segment's log_size, or a deployment constant) so one
  published commitment pins them all. (Per-segment-commitment variant deferred.)
- **Re-pin `VOUCHER_CHECK_COMMITMENT` for v8 + the chosen uniform log_size.**
  Compute it by proving one uniform-size segment and reading
  `program_commitment_of_proof`. Add a drift-guard test (the old one was
  retired) so future AIR/ELF changes fail loudly.
- **Policy = MOBILE** end-to-end (prove + verify) — the chain proofs are
  mobile-shape; the verifier must use the matching policy.

## ⚠ FINDING (2026-06-15, while grounding W0): canonical-shape proving is a HARD prereq

`prove` collects `log_sizes` per-component from `active_components` (ONLY active
chips) at each chip's natural trace height (`src/prove.rs:532,672`);
`verify_standalone` requires the whole `log_sizes` vector to match the published
commitment (the preprocessed Merkle root). Therefore:

- The transition's segments are HETEROGENEOUS (e.g. the scalar_mult segment has
  RistrettoEcallChip huge; the SMT-recompute segment has it absent) → different
  active sets + different per-chip heights → **different `log_sizes` → different
  commitments**, and the shapes are **witness-dependent** (different vouchers
  trace differently).
- So one shared commitment is NOT obtainable by "padding the last segment"
  (`chain_standalone.rs` only works because both tiny segments hit the
  `LOG_N_LANES` floor), and per-segment commitments shipped with the voucher are
  NOT verifiable (the verifier can't confirm an opaque root is "voucher-check at
  shape X", and shapes vary per voucher).
- The only sound, witness-independent way to publish ONE commitment that
  verifies every voucher's chain is **canonical-shape proving**: force every
  chip in every segment to a fixed per-chip `log_size` (worst-case maxima, all
  components present). This is `program_id.rs`'s flagged future-work, and it is
  a PREREQUISITE for the trustless-chain federation, not optional.

W0 is therefore a sub-project, not a re-pin. Open design + decision needed
before W1-W4.

### Measured (2026-06-15, `measure_segment_log_sizes`, release, 100K segments)

76 segments; **4 distinct commitments** across the proved archetype sample
(masks 21/22/27 components). Per-chip max `log_size` profile (chip_idx 0..30):
`[CPU 17, BLAKE2B 14, BLAKE2B_BOUNDARY 17, MEMORY 19, MEMORY_PAGE 10,
MEMORY_MERKLE 6, MEM_ROOT_BND 4, REG_MEM 18, REG_BND 4, REG_CLOSING 4,
PROG_BND 4, PROG_MEMORY 18, JUMP_TABLE 12, RANGE256 8, BITWISE_LOOKUP 8,
POWER_OF_TWO 6, POPCOUNT 0, BITCOUNT 0, BYTE_TO_BITS 8, MUL 15, BITWISE 14,
COMPARE 14, DIVREM 13, RISTRETTO 4, RIST_ECALL 7, COMB_TABLE 10,
FIXED_BASE_CONSUMER 11, COMB_ANCHOR 6, COMB_SCALAR_BND 5, COMB_COMPRESS 6,
COMB_COMPRESS_OUTPUT 5]`. Release prove ~5-12s per 100K segment.

**Forcing set** = the *variable* preprocessed-bearing chips (those whose
preprocessed period scales with op count): `BLAKE2B(1)`, `BLAKE2B_BOUNDARY(2)`,
`MEMORY_PAGE(4)`, and the ristretto chips `RISTRETTO(23)..COMB_COMPRESS_OUTPUT(30)`
(except the fixed `COMB_TABLE(25)`). The fixed-table preprocessed chips
(`PROG_MEMORY`, `JUMP_TABLE`, `RANGE256`, `BITWISE_LOOKUP`, `POWER_OF_TWO`,
`BYTE_TO_BITS`, `COMB_TABLE`) are already uniform. The big non-preprocessed
chips (`CPU`, `MEMORY`, `REGISTER_MEMORY`, `MUL`/`BITWISE`/`COMPARE`/`DIVREM`)
do NOT affect the commitment and need no forcing.

**Cost driver:** `BLAKE2B_BOUNDARY(2)` peaks at **log 17 (131072 rows)** in the
crypto segments and is active (variable) in every segment. Forcing it
present+uniform at log 17 everywhere roughly **2× per-segment prove cost**
(blake2b is the priciest chip/row). The ristretto chips are small (log ≤ 11),
so forcing them is cheap; Blake2bBoundary is the expensive one.

### Two implementation paths (DECISION NEEDED)

- **(A) Canonical-shape proving.** Thread a per-chip `min_log_size` into the
  ~12 variable preprocessed-bearing chips' trace-gen (`TraceBuilder::new(
  natural.max(min))`), force them always-present (empty→floor), prove every
  segment at the canonical profile → one stable commitment. Aligned with the
  existing one-commitment model + `verify_chain_standalone`. Cost: cross-cutting
  prover refactor (~12 chips + erased layer + prove path) AND ~2× per-segment
  prove time (Blake2bBoundary @ log 17 everywhere). Tightly couples with
  `proving-time.md`.
- **(B) Separate program-identity commitment.** Commit `PROGRAM_MEMORY`'s
  preprocessed columns as their own value bound by the STARK, and have
  `verify_chain` pin program identity to THAT (per segment) while letting the
  shape-dependent rest of the preprocessed root vary freely. No canonical-shape
  forcing → no cost blowup. Cost: a PCS/commitment-structure + proof-format
  change with its own soundness surface (the sub-commitment must be bound to
  the committed columns, not a free side-hash). Decouples identity from shape.

Recommendation: lean (A) for alignment unless the ~2× cost is unacceptable, in
which case (B) is the cost-avoiding alternative (heavier proof-structure work).

### W0 outcome (built 2026-06-16): canonical-shape (A) + a 2-entry allowlist

Implementing (A) surfaced a refinement the fork above missed: forcing each
chip's `log_size` is NOT sufficient for a single commitment, because TWO
forcing-set chips — `RistrettoFixedBaseConsumerChip` (idx 26,
`IsFinalAccProducer`/`FinalAcc*` gated on `real_n_rows`) and
`RistrettoCombCompressChip` (idx 29, `IsUnityCheck`/`IsOutputProducer`/
`CallIdx`/`IsCoordInputConsumer` gated on `real_n_rows`) — have preprocessed
*content* (not just size) that depends on the per-segment fixed-base-scalar-mult
("comb") count. So a comb-free segment and a comb-bearing segment get different
commitments even at the same forced `log_size`. The other 8 forcing-set chips
are pure-positional (witness-independent preprocessed period/table).

Rather than the risky positional-at-fixed-M comb-chip surgery (which would touch
the just-landed ristretto-ts AIR) OR path (B), we MEASURED the shape count:
`measure_comb_preproc_shapes` over the reference transition (7.56M steps, 76
segments of 100k) found comb calls in **exactly 1 of 76 segments** (histogram
`{0 calls: 75, 1 call: 1}`) ⇒ **only 2 distinct commitments**. The locked
canonical profile (`measure_canonical_profile`, per-chip MAX natural `log_size`
over ALL 76 segments) is `VOUCHER_CHECK_CANONICAL_PROFILE` =
`[0,14,17,0,10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4,7,0,11,6,5,6,5]`
(only the forcing set is non-zero; `BLAKE2B_BOUNDARY` @ 17 is the cost driver,
confirmed as the global max — it ranges 15-17).

**Chosen: (A) + commitment ALLOWLIST.** `zkpvm::prove_canonical(side_note,
profile)` forces the full 31-component set present (constant mask) + the
forcing-set chips to the profile. The chain ships its segments as before; the
verifier uses `zkpvm_verifier::verify_chain_standalone_allowlist(proofs,
&{C_0,C_1}, expected_initial_root, max_log_size, MOBILE)` — each segment's
commitment must be in the small published set. `{C_0, C_1}` is witness-
independent (a function of the comb count + profile, not of the scalars), and a
foreign program matches no `C_k`, so program identity is still pinned. Larger
transfer batches (more comb calls per segment) extend the allowlist with
`C_2, …` (a documented scaling follow-up; bounded by segment-size / comb-cost).
This adds NO AIR/constraint changes and NO proof-format change — only the
`min_log_size` threading + the allowlist verifier.

## Steps

- **W0 — CANONICAL-SHAPE PROVING (was: re-pin).** Define a canonical per-chip
  `log_sizes` profile (each chip's worst-case height for a bounded segment, all
  31 components present even if their main trace is empty). Add a prove mode
  that pads each chip's trace to its canonical `log_size` so the proof's
  `log_sizes` == the canonical profile regardless of segment content/witness →
  one stable commitment. Validate: two structurally-different real segments now
  produce the SAME commitment. Then prove one canonical segment, re-pin
  `VOUCHER_CHECK_COMMITMENT`, add a drift-guard test. (Soundness: padding rows
  are `is_real=0`, inert — but confirm no chip's constraints break at a forced
  larger log_size, and that an always-present-but-empty chip is sound.)
- **W1 — prover extension `prove_chain` + `verify_chain`.** New `#[msg]`s:
  `prove_chain(program_id, witness) -> Vec<u8>` (bincode `ChainProof`),
  `verify_chain(program_commitment, chain_hash, public_bytes, return_bytes,
  peer_prefix) -> u8` (fetch blob → `verify_chain_standalone` →
  io-hash check on the final segment). Keep the single-shot `prove`/`verify` for
  small programs. Unit test: prove a tiny multi-segment program, verify through
  the messages (round-trip + forgery reject).
- **W2 — clerk-bridge dispatch.** `dispatch_external_proof` → `verify_chain`
  (the voucher's `proof.bytes` now addresses the chain blob). `set_prover`
  commitment is the uniform-size v8 commitment. Adversarial paths unchanged
  (forged hash → blob miss → reject).
- **W3 — producer + e2e.** Move the real `SuccinctTransitionWitness` producer
  (today only in `prove_transition.rs`) into a helper the federation e2e calls:
  build witness → `prove_chain` → CAS-put → voucher carries the blob hash.
  Un-skip §5h happy path (real-STARK accept) + add a forged-voucher-rejects-on-
  real-STARK case. (May gate behind a slow/ignored marker given prove time.)
- **W4 — validation.** `chain_standalone` + the new W1 unit test + the e2e
  happy/forgery; rebuild the prover cdylib; confirm fmt/clippy clean.

## W1-W3 outcome (built 2026-06-16)

Landed on `voucher-state-transition`. A receiving bank verifies a peer's
segmented conservation chain end-to-end.

- **W1 (prover extension).** `prove_chain(program_id, witness) -> Vec<u8>`
  (trace → `segment_bounds` → per-segment `prove_canonical` against the pinned
  `VOUCHER_CHECK_CANONICAL_PROFILE` → `bincode(Vec<Proof>)` chain blob; caller
  CASes it) + `verify_chain(program_commitment, chain_hash, public_bytes,
  return_bytes, peer_prefix) -> u8` (`blob_get` → reverse-resolve the canonical
  commitment ALLOWLIST from `program_commitment` →
  `verify_chain_standalone_allowlist` on a 512 MiB-stack thread → io-binding on
  the final segment). Context-free cores `prove_chain_blob` / `verify_chain_blob`;
  single-shot `prove`/`verify` kept.
- **W2 (clerk-bridge).** `dispatch_external_proof` dispatches `verify_chain`
  (was `verify`); `voucher.proof.bytes` now addresses the chain blob — wire
  shape unchanged (one hash). The allowlist reverse-lookup means no bridge data
  change.
- **W3 (federation e2e).** `build_conservation_transition` producer (a
  self-contained `VecLedger` transition registered by bank A's clerk key, so
  the witness's `issuer` matches the peer pubkey the bridge reconstructs
  `public_bytes` from); §5h happy path un-skipped + gated on
  `VOS_FEDERATION_REAL_STARK`: build witness → `prove_chain` → CAS → External
  voucher → bridge `verify_chain` → redeem, plus a forged-root-on-real-STARK
  reject (the proof's io-binding pins the genuine roots — the property a bare
  signature could not enforce). Validated: `chain_blob_roundtrip` (accept /
  forged-io reject / non-allowlist reject) + the e2e happy path.

### Cross-node blob delivery — gated on RECURSION, not a manifest

The single `bincode(Vec<Proof>)` chain blob is ~N×1 MiB (tens of MiB for the
~76-segment transition), exceeding the **8 MiB single-shot cross-node frame
cap** (`MAX_FRAME_BYTES`; chunked transport unimplemented). So the e2e seeds
the chain blob on the receiver's node locally — the verification it exercises
is delivery-agnostic.

The deferred "manifest-of-hashes + per-segment fetch" fallback was considered
but NOT built: **recursion** (`recursion-spike.md`) collapses the N-segment
chain into ONE ~1 MiB aggregate proof — under the 8 MiB cap, a single-blob
fetch, a one-proof verify that also relieves the 512 MiB-stack pressure — and
supersedes `verify_chain` entirely, so a manifest would be throwaway.
Performance work (precompiling the guest's dominant blake2b) shrinks the chain
(fewer segments) but won't reliably reach a single sub-8-MiB blob; recursion
is the delivery fix. Cross-bank delivery is gated on recursion (preferred) or
generic chunked transport.

## Non-goals

- Proving-time optimization (`docs/plans/proving-time.md`) — separate, after.
- The settlement venue (neutral cross-bank finality) — separate architecture.
- Track 2 hardening (keys/ACLs/auth-join) — separate.
