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

## Non-goals

- Proving-time optimization (`docs/plans/proving-time.md`) — separate, after.
- The settlement venue (neutral cross-bank finality) — separate architecture.
- Track 2 hardening (keys/ACLs/auth-join) — separate.
