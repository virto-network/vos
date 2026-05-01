# zkpvm — security considerations

A guide for deployers who want to use zkpvm in the wild.  Read this
alongside [`STATUS.md`](./STATUS.md) (which proves *what* is bound)
and [`README.md`](./README.md) (which says *how* to call the API).

This document is descriptive: it spells out what a successful
verification *proves* about a PVM execution, what it *does not*
prove, and which inputs the deployer is responsible for providing
honestly.  It is not a formal security argument — see CONSTRAINTS.md
plus the per-phase commit messages for the integer-vs-field
soundness reasoning.

## Trust boundary

| Input to `verify_standalone(proof, hash)`        | Trusted? | Source                                        |
|---                                               |---       |---                                            |
| `proof.format_version`                           | NO       | Verifier rejects any value ≠ `PROOF_FORMAT_VERSION`. |
| `proof.stark_proof`                              | NO       | Cryptographically verified by stwo.           |
| `proof.claimed_sums`                             | NO       | Constrained: per-component logup must sum to 0. |
| `proof.log_sizes`                                | NO       | Capped by `DEFAULT_MAX_LOG_SIZE` (overridable). |
| `proof.initial_state` / `proof.final_state`      | partial  | Merkle-committed with the trace; deployer must publish what *should* match. |
| `proof.pcs_config`                               | partial  | Used as-is; affects security level.  See "Proof shape" below. |
| `hash` (preprocessed commitment)                 | YES      | Caller-supplied: this IS the program identity. |

The verifier accepts the proof iff:

1. `format_version` matches.
2. No `log_size` exceeds the cap.
3. `claimed_sums` length matches the verifier's component count.
4. The proof's `commitments[0]` (preprocessed Merkle root) equals
   the caller-supplied `hash`.
5. Per-component logup sums total exactly zero (no lookup imbalance).
6. The STARK proof verifies under the proof's own `pcs_config` and
   the deterministically-drawn lookup challenges.

## What a verified proof guarantees

A proof verified against `hash = H(P)` for program `P` proves that:

- **Execution shape**: the trace consists of N steps, each one a
  decoded PVM instruction at a basic-block-starting PC of `P`, with
  the canonical opcode / register / immediate / flags decoding.
  The bytecode-vs-trace binding lives in `ProgramMemoryChip`
  (Phases 13a/b/c/f).

- **Boundary state**: `proof.initial_state` is the register file +
  PC + timestamp + memory commitment at trace start;
  `proof.final_state` is the same at trace end.  Both are bound to
  the actual trace contents by the boundary chips.

- **Per-step semantics**: each ALU / branch / load / store / shift
  / rotate / bitmanip / divrem / mul / compare / cmov / move /
  jump / ECALL / Trap / Sbrk row satisfies the AIR's per-opcode
  constraints.  See `STATUS.md` for the per-opcode breakdown of
  *which* semantic property is bound.

- **Memory consistency**: every byte read at `(addr, ts)` matches
  the most recent write to that byte at `ts' < ts`, plus the
  initial memory image at `ts = 0`.  The byte-level
  `MemoryAccessLookup` enforces this independently of the
  per-step memory address calculation.

- **Register consistency**: every `regs_before[r]` at step n
  matches `regs_after[r]` at the most recent step that wrote `r`,
  or `initial_regs[r]` if no prior step wrote it.  Enforced by the
  per-step `RegisterMemoryLookup` (Phase 9).

- **Control-flow continuity**: step n+1's `pc` equals step n's
  `next_pc`; static branch / jump targets equal `pc + sign-
  extend(offset)`; indirect jumps land in the program's
  `jump_table`; Trap / Sbrk admit no successor row.

- **Blake2b precompiles**: every `Blake2b` ECALL row's `(h, m, t,
  f)` block is correctly compressed for 12 rounds — bound by the
  Blake2bChip (Phase 8).

## What a verified proof does NOT guarantee

- **Program intent**: the verifier only checks that the bytecode
  was executed correctly, not that the bytecode is doing what the
  user thinks it's doing.  Auditing the bytecode is the deployer's
  responsibility.

- **Public input authenticity**: `proof.initial_state.registers` and
  `proof.initial_state.memory_commitment` are committed to the
  trace, but the verifier has no way to check whether they match
  what the deployer *intended* to be the public input.  The
  deployer publishes `(hash, expected_initial_state,
  expected_final_state)` out of band and rejects any proof whose
  boundary states don't match.

- **Liveness / termination**: a proof is only generated for traces
  that the prover decided to trace.  A malicious prover can refuse
  to prove anything; the verifier sees no proof and rejects.  This
  is a liveness concern, not a soundness concern — but deployers
  should plan for it (timeouts, alternative provers).

- **Side-channel resistance**: zkpvm is not constant-time and
  leaks timing information about the trace shape via prover
  resource use.  Don't run the prover on inputs you can't tolerate
  leaking timing information about.  The verifier itself is
  data-independent in its happy path.

- **Resource bounds beyond `log_size`**: the cap on
  `proof.log_sizes` bounds verifier CPU/memory.  But a deployer
  who uses a custom `verify_standalone_with_max_log_size` cap
  larger than `DEFAULT_MAX_LOG_SIZE` is opting into proportionally
  more verification cost.  Pick the smallest cap that admits your
  honest-prover shapes.

- **Cross-program isolation**: the proof binds to *one* program
  (one preprocessed Merkle root).  If two programs compose, the
  deployer must verify both proofs and check the boundary
  states chain.

## Proof shape (`pcs_config`)

`production_pcs_config()` (used by the no-arg `prove`) sets:

- FRI blowup factor 16 (`log_blowup_factor = 4`)
- 19 FRI queries
- 20-bit proof-of-work

This corresponds to ≈96-bit conjectured security against the
soundness error of FRI for the trace sizes zkpvm produces.  A
deployer who needs more or less can use `prove_with_config` with a
custom `PcsConfig` — but the verifier accepts whatever `pcs_config`
the proof carries (it's used as-is).  This means **a malicious
prover who can convince a deployer to accept a weaker config can
forge proofs at that weaker security level**.  Deployers should
either:

1. Hard-code a check that `proof.pcs_config == known_config`
   before calling `verify_standalone`, OR
2. Wrap `verify_standalone` in a deployment-specific function that
   inspects `proof.pcs_config` and rejects weaker-than-policy
   configs.

**Phase 49 update**: there is now a built-in `PcsPolicy::STANDARD`
check.  `verify` and `verify_standalone` reject any proof whose
`pcs_config` falls below the floor (`pow_bits ≥ 20`, `n_queries ≥
19`, `log_blowup_factor ≥ 4` — what `production_pcs_config()`
generates).  Deployers needing strictly more (e.g. higher pow_bits
for a higher-stakes deployment) call
`verify_*_with_pcs_policy(&PcsPolicy { min_pow_bits: 24, .. })`.
Deployers running test harnesses with intentionally-weak configs
call the same with `min_pow_bits = 0`, etc.  The default rejects
weak configs; opt-in to weaker policy is explicit.

## Deployment checklist

Before pointing real users at a deployed verifier:

- [ ] **Pin `PROOF_FORMAT_VERSION`** — both the prover and verifier
  binaries must be built from the same commit.  A version mismatch
  is rejected, but a same-version build with subtly different
  AIRs (e.g., a fork) is not.  Pin the source tree at deployment
  time.
- [ ] **Publish `(hash, expected_log_sizes, expected_pcs_config,
  expected_initial_state)`** — every proof from this program
  should match these.  The verifier checks `hash`; the deployer's
  glue code must check the rest.
- [ ] **Audit the bytecode** — the verifier doesn't.  Soundness of
  `prove → verify` is independent of what the program *does*.
- [ ] **Set `max_log_size`** based on your honest-prover shapes.
  `DEFAULT_MAX_LOG_SIZE = 24` is a reasonable starting point but
  almost always loose for a specific program.
- [ ] **Decide on `pcs_config` policy** and enforce it before
  `verify_standalone`.  See "Proof shape" above.
- [ ] **Plan for liveness failures** — a missing proof is not a
  rejected proof.  Deploy a fallback or alternative-prover path.
- [ ] **Consider the `javm` interpreter your trusted reference** —
  zkpvm proves that a trace matches javm's PVM semantics.  Bugs
  in javm are bugs in zkpvm by construction; track its release
  notes alongside zkpvm's.

## Reporting issues

Soundness or verifier-DoS bugs: file a private issue or contact
the maintainers directly.  Bytecode-level bugs (interpreter
divergence, off-by-one in javm) belong in the javm tracker.

## Stability notes

- `PROOF_FORMAT_VERSION` is the version-bump knob.  See `lib.rs`'s
  "API stability" section for which items are versioned and which
  sub-modules are internal.
- Stwo and javm are pinned to git revs in this crate's
  `Cargo.toml` (no crates.io release yet for either).  A deployer
  who vendors zkpvm should also pin those.
- The proof format itself is *not* spec'd outside the source.  A
  bytewise-compatible Rust struct on the same `PROOF_FORMAT_VERSION`
  is the only guarantee.  For long-term archival, store proofs
  alongside the verifier binary that produced them.
