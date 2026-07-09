# The masked image root — the Level-2 entering-image pin

Status: DESIGN (not implemented). Records the problem the entering-image anchor
runs into for witness-INJECTING provable programs and the masked-root approach
that closes it. Level-1 (the manifest-carried anchor + `verify_chain` check)
ships now; this note is the Level-2 pin.

## 1. What ships now (Level-1)

The chain manifest carries an `initial_root` and the prover extension's
`verify_chain` anchors segment 0's `initial_state.memory_root` to it (see
`ChainManifest` in `extensions/prover/src/lib.rs`, and
`work-result-contract.md` §5 for the proving seam). The manifest is
content-addressed, so wherever its hash rides — the External voucher's
`proof.bytes` on the federation money path — the entering root is a **committed,
signed, auditable** part of the statement. This makes the entering image
tamper-evident and brings the streaming CAS path to parity with the library's
`verify_chain_standalone_allowlist`, which anchors the same way.

What Level-1 does **not** do: prove the declared entering root is the *genuine*
program image. A producer builds the manifest to match its own segment 0, so the
anchor equality holds for any self-consistent chain — including one that entered
from a doctored image. Full soundness needs the verifier to pin the declared
root against a **published** value.

## 2. Why the catalog's `unpatched_image_root` cannot be that pin

The obvious published value is the program's initial image root, which
`vosx zk pin` measures as `unpatched_image_root` (page-Merkle root of the
transpiled blob's initial memory, `__VOS_WITNESS` still all-zero `.bss`).

It does not work, because of how a provable Task is invoked. The witness-
delivered ABI (keystone A9, now on master) delivers `(state, msg)` by **patching
the child's initial memory image at `__VOS_WITNESS`** — the same channel the
zkpvm tracer patches — so the live run and the traced run start from
byte-identical images (`live ≡ traced`). Consequences:

- The value the AIR binds as `segment[0].initial_state.memory_root` is the
  **patched** image root — witness bytes present in the buffer.
- The catalog's `unpatched_image_root` is the **unpatched** image root — zeros in
  that buffer.
- The two differ precisely in the `__VOS_WITNESS` region, and the witness is
  **secret and per-proof**.

So `patched_root != unpatched_root`, and a verifier cannot check
`manifest.initial_root == unpatched_image_root`. Worse, the witness region *must*
stay free (it is the input), so a naive "pin the whole image" rule is both wrong
(fails on honest proofs) and, if forced, would fix bytes that legitimately vary.

`unpatched_image_root` is therefore recorded today as a **diagnostic**, not a
verifier pin (its `ProgramPin` doc says so). Nothing in the verify path consumes
it.

## 3. The approach — a masked image root

Exclude the `__VOS_WITNESS` region from the hashed image, so the pinned value is
invariant under the witness while still fixing everything else (code, constants,
other initialized data):

```
masked_image_root(image, witness_addr, witness_cap)
    = image_root( image with bytes [witness_addr, witness_addr + witness_cap) zeroed )
```

Then, for any witness value `w`:

```
masked_image_root(patched_with(w)) == masked_image_root(unpatched) == M   (a per-program constant)
```

`M` is publishable (the catalog pins `masked_image_root`), and the verifier
checks the entering image against `M` while leaving the witness region
unconstrained — exactly the freedom the input needs, and no more.

## 4. What it requires (the hard part, deferred)

The check must compare against segment 0's *in-AIR* memory root, which today is
the **full** (unmasked) page-Merkle root the memory chips bind. Options, roughly
in increasing cost:

1. **Page-aligned witness buffer + excluded leaves.** If `__VOS_WITNESS` is
   page-aligned and a whole number of pages, the masked root is the full root
   with those leaves forced to the empty-leaf default. A verifier given the
   witness page indices could recompute — but the in-AIR `memory_root` still
   commits the real (patched) leaves, so this needs either (a) a second in-AIR
   **masked-root** column the memory chips also emit, or (b) a host-side masked
   recomputation the AIR is made to agree with. Sub-page buffers need
   leaf-level zeroing, which is messier.
2. **Anchor as a masked projection.** Bind, in the boundary layer, a
   `masked_memory_root` alongside `memory_root`, computed by the same
   `Memory{Page,Merkle,RootBoundary}Chip` machinery over the witness-zeroed page
   set. `verify_chain` then anchors `masked_memory_root == M`. This is the clean
   shape but adds an AIR column + constraints (a `page-merkle-binding`-style
   change, cf. `zkpvm/docs/plans/memory-merkle-binding.md`).
3. **Separate masked commitment.** Ship a small proof that segment 0's declared
   image, witness-zeroed, hashes to `M`. Heavier; avoids AIR changes.

Cross-cutting requirements regardless of option:

- Pin `witness_addr` **and** `witness_cap` in the catalog (the mask needs the
  span, not just the start; `witness_addr` is already pinned).
- The prover/verifier expose `masked_image_root(image, addr, cap)`.
- `vosx zk pin` measures and stores `masked_image_root`; the producer computes
  the manifest's `initial_root` as the masked root; `verify_chain` compares the
  masked segment-0 root to the catalog's `M`.

## 5. Recommendation

- Keep Level-1 as shipped (committed, auditable entering root).
- Treat `unpatched_image_root` as a diagnostic until this lands; do **not** wire
  any verifier to pin against it.
- When Level-2 is scheduled, option (2) — an in-AIR masked-root boundary column —
  is the JAM-portable shape and the one to spike first, gated by a parity test
  (`masked_image_root(patched) == masked_image_root(unpatched)` across witnesses)
  before any verifier trusts it.
