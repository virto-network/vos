# Draft for upstream Stwo issue (do not file from here)

File at: https://github.com/starkware-libs/stwo/issues/new

When ready to file, copy the body below.  Tone is "ask + provide context",
not "complain".  Goal: get a timeline indicator from the team.

---

## Title

> Lifted protocol: support AIRs with `LOG_CONSTRAINT_DEGREE_BOUND >= 2`

## Body

We're a downstream zkVM (`kunekt/zkpvm`, JAM PVM-bytecode prover built on Stwo's SimdBackend) attempting to migrate from `0790eba` to `v2.2.0` to capture the upstream perf cluster (#1304/#1305/#1306 parallel FFT/quotients/OOD, #1340 FRI jumps, #1342 BaseColumnPool, #1372/#1373 subdomain quotients).

The migration is blocked by what looks like an interim restriction in the new lifted protocol.  Wanted to surface it and ask for a rough timeline.

### What we observe

In v2.x the `MerkleChannel` impls for `Blake2sMerkleChannelGeneric<_>` (both byte-output `<false>` and M31-output `<true>` variants) live exclusively in `core::vcs_lifted::blake2_merkle`, not in `core::vcs::blake2_merkle`.  The non-lifted module only has the data structs.  So all proving paths now go through the lifted protocol.

Running `crates/examples` at v2.2.0:

```
$ cargo test --release poseidon
test poseidon::tests::test_simd_poseidon_prove ...
  ignored, AIRs with constraint degree >= 2 are not supported yet in the lifted protocol.
```

The Poseidon AIR has `max_constraint_log_degree_bound = log_n_rows + 2` (so `LOG_CONSTRAINT_DEGREE_BOUND = 2`, polynomial degree up to 4).  WideFibonacci has `LOG_CONSTRAINT_DEGREE_BOUND = 1` (degree up to 2) and passes — so the boundary is at LOG ≥ 2.

### Why this matters for us

Five of our chips have `LOG_CONSTRAINT_DEGREE_BOUND` ≥ 2:

| Chip | Bound | Why |
|---|---|---|
| `Blake2bChip` | 2 | G-function modular arithmetic |
| `MulChip` | 2 | RV-style 64×64 schoolbook accumulator |
| `CpuChip` | 2 | Op-flag products `is_real · is_xxx · linear` |
| `DivRemChip` | 3 | Sign-correction chains |
| `RistrettoChip` | 3 | 256×256 schoolbook over Curve25519 base field |

A rewrite to flatten everything to LOG = 1 with helper columns is feasible (~6–8 person-weeks across 5 chips per our scope estimate) but expensive enough to want a sense of whether the lifted-protocol support is days, weeks, or months out before committing.

### Questions

1. Is there an open PR / branch tracking degree-≥2 support in the lifted protocol?
2. Rough ETA (next-release / quarter / "no current plan")?
3. If "no current plan," is there a sanctioned interim path — e.g., a feature flag or alternative `MerkleChannel` impl — to keep degree-≥2 AIRs working on the v2.x perf path?  We'd be happy to send a small PR re-impl'ing `MerkleChannel` for the non-lifted `vcs::blake2_merkle::Blake2sMerkleChannelGeneric` if that's the right shape.

For context our migration scope doc lives at:
https://github.com/virto-network/kunekt/blob/zkvm/.wt_alt/crates/zkpvm/STWO_2.2.0_MIGRATION.md
*(adjust path before filing — depends on where the branch lands upstream)*

Thanks for the great prover.  Happy to provide more reproducer detail if useful.

---

## Filing checklist

- [ ] Update the migration-doc link path before posting (if the file moves)
- [ ] Optional: add the Poseidon `#[ignore]` line as a code-block screenshot in the Stwo team's tracker
- [ ] Subscribe to the issue so a response is visible without polling
