# Device and credential parameters under masking (c): the counts

A short computation for slice 7's pins (`slice-7-mobile.md`, pins I and J),
2026-10-25. The security tool (`pvm/proof/src/security.rs` at `f83f744b`)
copied into a scratch crate, run over `SecurityShape::variant_c()` of three
shapes [model]:
- **device, m = 16:** every segment chip at 2^16 rows (`DEVICE_REFERENCE`:
  10,016 sampled values, 5,177 constraints, relation width 265);
- **device, m = 14:** the same at 2^14, the auth kernel's tallest chip;
- **credential, m = 12:** a small recursion-style AIR (about 400 columns,
  320 constraints, width 5).

For each blowup and PoW, the least query count whose proven count clears
62 (the floor of 60 with format 37's 2 bits of margin) and whose
conjectured count clears 100. Then the rows a masked column reveals with
two offsets a column (`|O| = 2`, a next-row read): `4|O| + q(|O| + 1)`;
the randomizer needs `h ≥ 2 × revealed` (pin A's static check), `h` a
power of two (`log_mask_rows`), and `h ≤ N/4`, so every masked component
pads to `N ≥ 4h` rows.

| blowup | PoW | queries (powers / affine) | revealed | h | rows a component, at least |
|---|---|---|---|---|---|
| 2 | 20 | 86–87 / 85 | 263–269 | 1,024 | 2^12 |
| 2 | 24 | 77–79 / 77 | 239–245 | 512 | 2^11 |
| 4 | 20 | 43 / 43 | 137 | 512 | 2^11 |
| 4 | 24 | 39 / 39 | 125 | 256 | 2^10 |
| 8 | 20 | 29 / 29 | 95 | 256 | 2^10 |
| 16 | 20 | 22 / 22 | 74 | 256 | 2^10 |

The three shapes agree within one query; the query term binds everywhere
(the conjectured floor of 100 binds first at blowup 16).

**Findings:**
1. **Format 37 as reserved (blowup 2, 86 queries, PoW 20, batching by
   powers) counts 61.86 proven bits under (c)** at its reference shape,
   against 62.10 counted on the unmasked shape it was reserved with: it
   clears the floor of 60 but not its own margin. Under (c) it needs 87
   queries, or affine batching (62.85 at 86). A masked device format is
   counted on its masked shape.
2. **At blowup 2 the mask pads every masked component to 2^12 rows**
   (h = 1,024). A component with no next-row read (`|O| = 1`) reveals
   `4 + 2q` = 176 rows at 86 queries, so `h = 512` and 2^11 would do: a
   per-component `h` is worth having.
3. **For a small AIR the padded floor costs the same at any blowup:** a
   component at its floor commits `4h × 2 × blowup` cells (masked columns
   at `n + 1`), 2^14 a column at blowup 2, 4 and 8 alike, while the proof shrinks
   with the queries (85 → 43 → 29). The credential AIR, whose components
   all sit at the floor, should take blowup 4 or 8. The device profile,
   whose CPU and memory chips are taller than the floor, pays blowup on
   them and gains it back on the floor and in bytes: measured, not
   counted (7.16).
4. **PoW 24 instead of 20** halves the floor at blowup 2 and saves 8
   queries, for about 16× the grinding: on the phone about 2^24 Blake2s
   hashes, a few hundred milliseconds [est], too dear for a 1 s gate.
5. **PoW is a phone lever the other way too** (draft 1's review, M9): PoW
   20 is 0.028 s on 8 x86 threads (`proving.md` §4), so about 0.1 s on the
   phone on average and about 0.3 s at the 95th percentile [est, ARM
   factor 3.5]. Fewer bits cost a few queries, and the floor stays:

   | shape | blowup | PoW | queries | proven | conjectured | rows at least |
   |---|---|---|---|---|---|---|
   | device, m = 16 | 4 | 16 | 47 | 62.09 | 110 | 2^11 |
   | device, m = 14 | 4 | 16 | 47 | 62.30 | 110 | 2^11 |
   | credential | 4 | 16 | 47 | 62.66 | 110 | 2^11 |
   | device, m = 16 | 2 | 16 | 95 | 62.19 | 111 | 2^12 |
   | device, m = 16 | 8 | 16 | 32 | 63.01 | 112 | 2^10 |

   PoW 14 at blowup 4 needs 49 queries (62.05). The phone gates record the
   95th percentile, where the grind's tail shows.
6. **Bytes at blowup 2** (the review's H1): the kit's floor proof was 1.02
   MB at 38 queries, unmasked, over 4,655 columns; masking added ×1.31 in
   bytes on the wrap. At 86–87 queries that is about 3 MB on the floor's
   columns and about 1.3 MB on a shape of about 2,000 columns (BLAKE2b
   gone) [est], against pin J's 1.5 MiB. 7.0a measures it.
