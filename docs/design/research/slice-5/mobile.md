# Slice 5: proving on a phone — the baseline and the path to sub-second

Date 2026-10-16. Worktree `.worktrees/s5-mobile`, branch `spike/s5-mobile` from
`a6f6adbc`. Local commits `b6ba6afc` (code) and `d157d72f` (run logs); nothing
pushed, and vos-core only read. Paths: `SM` = `spikes/s5-mobile`, `R` =
`SM/runs`, `P` = `pvm/proof`.

**Tags:** **[measured]** on this x86 box (Core Ultra 7 155H: 6 P-cores with
HT, 8 E-cores, 2 LP-E; AVX2, no AVX-512); **[modelled]** arithmetic over
measured parts; **[projected]** a model applied to a setting not run (masking,
phones, chips); sources **[read]** in our tree, **[src]** another project's
source, **[docs]**, **[paper]**, **[2nd]** secondary. External figures come from
a delegated source and doc read (clones in `.../s5/mobile-research/`).

**Caveat:** two other spikes loaded the box (load 3–27). Times are the best of
3–5 runs over several passes (`SM/scripts/best.py`); equal shapes varied up to
2× between passes, so read one time as ±30%. Steps, columns, cells, bytes and
RSS are exact. Calibration: `mobile_bench 14` runs in 0.73 s here; the roadmap
quotes about 1.7 s idle on older code.

## 0. The answers

**1. The statements as PVM kernels** [measured; the phone column projected].
"Floor" is the shape without the page-Merkle boundary, a cost proxy (§3, lever
2); the phone factor is §5.

| statement | steps | segments (32k) | 4 P-cores, as built | 4 P-cores, floor | phone, floor masked |
|---|---|---|---|---|---|
| auth: a vos-tree path at 10^6 rows + a nullifier | 12,951 | 1 | 1.70 s, 2.1 GiB | 0.71 s, 0.9 GiB | 1.2–3.1 s |
| pay: a row read + balance ≥ amount | 14,200 | 1 | 2.24 s (4 threads) | 0.70 s | 1.2–3.1 s |
| ed25519, software | 862,284 | 27 | 2.28 s per segment (4 threads) | 1.03 s per segment | 47–120 s |
| ES256 passkey, software | 4,321,908 | 132 | 2.33 s per segment (4 threads) | 1.27 s per segment (4 threads) | 4–10 min |

**2. A small proof's time.** The page boundary is **56% of auth's cells and 91%
of an empty kernel's**: the empty kernel (186 steps) takes 2.66 s on one thread
with it and **0.043 s** without (about 20 ms fixed + 20–30 ms PoW). Above that
floor, time is proportional to committed cells: about 53 ns per cell on one
thread, about 19 ns on 4 P-cores [measured].

**3. The levers to sub-second, in order:** boundary off for single-segment
kernels −58% [measured proxy]; a lean kernel plus narrow BLAKE2b −54% of the
rest [modelled]; a Merkle-path precompile or a Poseidon2 tree about −47% more
[modelled]; masking (c) ×1.7 [projected]. Blowup 2 gives −20% and PoW about −30
ms [measured]. No help: Poseidon2 Merkle on the prover (5–13× slower), STANDARD
(2×), more than 4 threads (small; 2P+4E is slower than 4P).

**4. Signatures in software are hopeless; with chips they are not.** At about
1,500 cells per step: SHA-256 5,091 steps per block, SHA-512 7,350, P-256 verify
4.29M, ed25519 verify 862k [measured]. Chips [modelled]: SHA-256 50–100k cells
per block, SHA-512 100–200k, P-256 verify 1.6–3.5M, ed25519 about 4M on a q·m
field chip or about 18M on today's Ristretto rows. With chips, either signature
statement is about 8–10M cells, beside auth.

**5. Phone.** A phone takes our 4-P-core time × 1.0–1.5 (A17 Pro, A18 Pro,
Snapdragon 8 Elite), × 1.1–1.7 (Snapdragon 8 Gen 3) or × 1.8–2.6 (Tensor G3/G4)
[projected]. qemu-aarch64 proved `auth` **byte-identically to x86**, and it
verifies [measured].

**6. Verdict.** None is sub-second today. auth and pay with the item-3 levers:
0.4–0.9 s masked on Apple-class phones, 0.7–1.6 s on Tensor [projected]. The
signatures need precompile chips (software is 50–300× too slow); with chips
0.4–0.6 s (Apple) and 0.7–1.1 s (Tensor), or 0.9–2.4 s on today's
Ristretto-width rows.

## 1. What was built

- **`SM/statements`** (no_std): the four statements plus `empty`, `sha256`,
  `sha512`, `p256_prehash`. **auth**: the member row's one-key vos-tree
  multiproof (20 branches at 10^6 rows) through spike 3's compress-level
  `window_kernel::verify`; value H(secret); output the nullifier H(secret ‖
  scope). **pay**: a 96-byte row (owner = H(secret), balance, currency), 21
  branches, then balance ≥ amount; output a spend tag. **ed25519**:
  `ed25519-dalek` 2.2 verify with SHA-512. **passkey**: authData's rpIdHash and
  UP flag, `"type":"webauthn.get"` and the base64url challenge in a 134-byte
  clientDataJSON, then `p256` 0.13 ECDSA over authData ‖ SHA-256(clientData).
- **`SM/guest`**: one actor, one `#[attestable]` method per statement; `derive`
  gives kernels of 2.8–88 KB, selected by method id.
- **`SM/harness`**: `gen` builds the 10^6-row tree, keys and signatures and
  checks every statement natively, refusals included; `trace` and `prove` use
  spike 3's sparse chain-path tracer and `prove_canonical_masked`, with
  `S5_CONFIG`, `S5_MASK`, `S5_DROP=boundary`, `RAYON_NUM_THREADS` and `taskset`
  pinning. Every proof except the floor proxy is verified standalone.
- **The floor seam** (`P/src/chips/memory.rs`, `S5_SPIKE_TOUCHED_BYTES`): the
  ledger gets ts=0 and closing entries only for the bytes accessed, as a shape
  without the boundary would; the boundary chips (and an unused AND table) are
  masked out. Relations no longer balance, so it measures cost only.

## 2. The statements, measured (Blake2s, MOBILE 4/38/20, kernel shape)

**Shapes** [measured]. "Floor" drops BLAKE2B_BOUNDARY, MEMORY_PAGE,
MEMORY_MERKLE and MEMORY_ROOT_BOUNDARY, and the AND table when no BLAKE2b chip
remains.

| kernel | mask (chips) | columns as built / floor | cells as built / floor | max log | boundary compressions (pages) |
|---|---|---|---|---|---|
| empty | `0x807cfffd` (21) | 4,530 / 1,666 | 51.6M / 0.5M | 16 / 12 | 177 (5) |
| auth, pay | `0x807cffff` (22) | 7,511 / 4,655 | 84.8M / 34.1M | 17 / 16 | 320–322 (8) |
| ed25519 segment 5 of 27 | `0x807cfffd` (21) | 4,530 / 1,666 | 97.1M / 49.6M | 17 | 223 |
| passkey segment 5 of 132 | `0x807cfffd` (21) | 4,530 / 1,666 | 98.9M / 51.4M | 17 | 201 |

auth's floor cells [measured]: CPU 12.8M (38%; 781 columns at 2^14), BLAKE2B
12.2M (36%; 2,981 columns at 2^12 for 25 compressions at 518 steps each), MEMORY
3.5M (10%), REGISTER_MEMORY 3.0M (9%), tables 1.7M (5%; PROGRAM_MEMORY 2^15, AND
2^16), ALU 0.8M. Signature segments run 1,514 / 1,569 cells per step (CPU 52%,
registers 25%, memory 14%). Neither signature kernel uses BLAKE2b or Ristretto;
the precomputed-table ed25519 build takes the same 862,284 steps. Per-chip widths are the audit's §1.1 table (same AIR). Ristretto ids
110–114 are refused by `derive` (`derive.rs:630-641`) and take Ristretto, not
Edwards, encodings (`P/precompiles/src/ristretto.rs`) [read].

**Prove time (s), best observed** [measured]:

| kernel | shape | 1 thread | 4 threads | 4 P-cores | 4 E-cores | 2P+4E | 8 threads | 10 threads |
|---|---|---|---|---|---|---|---|---|
| empty | as built / floor | 2.66 / 0.043 | 1.24 / 0.052 | — / 0.044 | — / 0.063 | — / 0.056 | 0.85 / 0.056 | 1.08 / 0.079 |
| auth | as built / floor | 4.55 / 1.81 | 1.91 / 1.16 | 1.70 / 0.71 | 2.88 / 1.15 | 2.75 / 0.83 | 1.38 / 0.58 | 1.80 / 0.77 |
| pay | as built / floor | 5.42 / 1.99 | 2.24 / 1.00 | — / 0.70 | — / 1.15 | — / 1.14 | 1.41 / 0.60 | 1.61 / 0.64 |
| ed25519 segment | as built / floor | — / 2.65 | 2.28 / 1.23 | — / 1.03 | — / 1.79 | — / 1.60 | — / 1.03 | 3.24 / 1.60 |
| passkey segment | as built / floor | — / 2.69 | 2.33 / 1.27 | — | — | — | — / 1.01 | 5.05 / 1.05 |

**Memory, proof, verify** [measured]. Peak RSS as built / floor: empty 1.26 /
0.03 GiB; auth and pay 2.0–2.3 / 0.89–0.98 GiB; a signature segment 2.7 / 1.7
GiB, including the resident whole-kernel trace at about 355 B per step (1.5 GiB
more for passkey). Postcard proofs: empty 942 / 326 KB; auth 1.63 / 1.02 MB;
signature segment 1.03 MB / 437 KB. Native verify of as-built proofs: 10–38 ms.
A 64k-step signature segment without the boundary: 2.43 s on 4 threads (linear).

**Masked phone setting, (c) at blowup 2 / 76 queries** [projected; masking is not
runnable in our prover, and spike 2's prototype is one toy component]. Spike 2
measured (c)-mobile against MOBILE at time ×1.64–1.70, memory ×1.62–1.68, proof
×2.03–2.10. On our auth-floor stage split (1 thread), commits ×1.23 (0.76 → 0.94
s) and `stark_prove` ×2.24 (0.86 → 1.93 s) give **×1.70**. So auth's floor
masked: about 1.2 s on 4 P-cores, 1.5 GiB, 2.1 MB; as built masked: about 3.5
GiB, over the 3 GB app cap. Masking pads every masked component to ≥ 2^11 rows
(h ≤ N/4, h = 512; spike 2 §2.1) [read], so the empty floor's 1,666 columns
become about 3.5M cells and a masked empty kernel about 0.17 s on 4 P-cores
[projected]. A single signature segment is out of reach: ed25519 is about 1.3G
cells, roughly 35 GB at blowup 4 [modelled].

## 3. Where the time goes, and the levers

**Stage split, 1 thread** [measured]:

| kernel | trace gen | preprocessed commit | main commit | interaction | stark_prove (composition, OODS, FRI, PoW, decommit) | total |
|---|---|---|---|---|---|---|
| empty, as built | 4% | 2% | 28% | 16% | 50% | 2.65 s |
| empty, floor | 5% | 9% | 16% | 9% | 60% | 0.042 s |
| auth, floor | 6% | 3% | 30% | 14% | 47% | 1.80 s |
| ed25519 segment, floor | 7% | 3% | 35% | 12% | 44% | 2.64 s |

**Fixed costs** [measured]: PoW (20 bits) 32 ms on 4 threads (empty floor 50.7
→ 18.3 ms at pow 0); the rest of the empty floor (FRI to 2^15, composition, the
preprocessed and program trees) about 18 ms; the preprocessed commit 2–9%, and
witness-independent, so it can be done at install; a 2^16 table in a tiny kernel
(empty with the page-wide ledger and the AND table: 0.22 s against 0.052 s); the
page boundary at about 10k BLAKE2B_BOUNDARY rows per touched page (roadmap)
[read]. **Proportional** [measured fit, within 3% over auth and the ed25519
segment]: t ≈ 0.04 s + 53 ns per cell on 1 thread, 19–20 ns on 4 P-cores, 25–30
ns on 4 unpinned threads; about 27 B of RSS per cell.

**The levers** (auth unless stated):

| lever | effect | basis |
|---|---|---|
| 1. A shape per kernel (22 of 32 chips) | Floor time within noise (the Ristretto chips are 16-row padding). Proof 1.30 → 1.02 MB (−22%); audit −38% verify gas. The empty floor: 0.19 → 0.05 s. Under masking's 2^11 floor the full shape's 10,173 columns are about 21M cells against 3.4M: **about 6× the masked floor** | measured; the masked figure modelled |
| 2. One segment without the page boundary | 4 P-cores 1.70 → 0.71 s (−58%); 1 thread 4.55 → 1.81 s; 2.1 → 0.9 GiB; empty 2.66 → 0.043 s. Dropping the chips but keeping the page-wide ledger gives 1.20 s on 4 threads, so the ledger correction is small | measured proxy |
| 3. A lean kernel (spike 3's floor: about 170 steps per compression, no argument copy; about 5k steps) | CPU, registers, memory and program memory 20.6M → 10.0M cells | modelled |
| 4. Narrow BLAKE2b (per-compression I/O on its own row; audit: 2,981 → about 1,050 columns) | BLAKE2B 12.2M → 4.3M cells; with lever 3, 34.1M → 15.6M ≈ 0.35 s on 4 P-cores | modelled |
| 5. A Merkle-path precompile (the chip walks the path; CPU about 1.5k steps) | 15.6M → 8.3M cells ≈ 0.21 s | modelled |
| 5'. A Poseidon2-M31 membership tree (about 30 permutations, about 158 columns each) | BLAKE2B and the AND table gone; about 4–12M cells. Changes the spec's compress-level BLAKE2b | modelled |
| 6. Smaller minimum heights | The unmasked minimum (2^4) costs nothing. The real floors are the AND table (2^16), the 256-row tables and, masked, 2^11 per component: cut the floor shape's columns, or use (c) at 26 queries (h = 256, so 2^10) at blowup 8 | measured / read |
| 7. Settings, floor, 4 threads | Blowup 2 / 76: 0.75 s (4 P-cores 0.57 s, −20%), 1.87 MB. Blowup 8 / 26: 1.44 s, 751 KB. STANDARD: 2.40 s, 2.8 GiB, 591 KB. PoW 0: −0.03 to −0.12 s | measured |
| 8. Blake2s against Poseidon2-M31 Merkle | Poseidon2 is 7× (as built) to 5–13× (floor) slower on 4 threads: its commit runs on CpuBackend, at 8 elements per permutation against Blake2s's 16. **Device proofs stay on Blake2s**; the recursion pays about 5× (audit) for one Blake2s segment | measured |
| 9. Threads | 1 → 4 threads ×1.6–2.5; 4 → 8 ×1.3–2.0; 10 no better than 8. 4 P-cores beat 4 E-cores ×1.6. **2P+4E is slower than 4P**: rayon splits evenly and the E-cores straggle, so weight work by core class | measured |

**Is the boundary needed when nothing chains?** Not for continuity: there is no
next segment to link. A single segment still needs its initial data and its
public arguments bound, which a much cheaper shape can do:

| part of the image | how it is bound |
|---|---|
| code | PROGRAM_MEMORY, preprocessed |
| data | a small preprocessed data table in the program id feeds the ts=0 entries |
| stack and heap | first touches constrained to zero |
| private arguments | free: they are witness |
| public arguments and output | the φ9..12 io-hash |
| final image | not committed |

Spike 2 §2.7 already has a single segment publishing no memory root, so it
needs no salt page. Chained kernels still need the boundary, or global memory.

## 4. Signature chips

**Software in our PVM** [measured steps; cells modelled at about 1,500 per
step]:

| operation | steps | cells | what dominates |
|---|---|---|---|
| SHA-256, per block | 5,091 | ≈7.6M | rotations as shift + shift + or (Xor 13%, ShloR32 13%, Or 12%) |
| SHA-512, per block | 7,350 | ≈11M | the same |
| P-256 verify (`p256` 0.13, prehashed) | 4,291,594 | ≈6.5G | carry emulation (Add64 29%, SetLtU 17%) |
| ed25519 verify (`ed25519-dalek` 2.2) | 862,284 | ≈1.3G | 64×64 products (Mul64 + MulUpperUU 15%) |

SP1 measured unpatched p256 verify at 3.87M cycles [2nd].

**How other systems accelerate them:**

| system | what | numbers | tag |
|---|---|---|---|
| SP1 (31-bit KoalaBear) | `SECP256R1_ADD` / `DOUBLE`, one row per point op | 1,599 / 1,591 main columns; `FieldOpCols` 126 (32 result + 32 quotient + 62 witness limbs, 8-bit limbs) for a·b − r − q·p = (x − 2^8)·w(x), u8 and u16 range checks | [src] |
| | SHA-256 | ShaCompress 80 rows × 206 columns, ShaExtend 48 × 128: 22.6k main cells per block. No SHA-512 syscall | [src] |
| | P-256 verify | 117k cycles patched, against 3.87M | [2nd] |
| RISC Zero | SHA-256 accelerator | 6 + 68 cycles per block; no SHA-512 | [docs] |
| | bigint2 | p256verify 82,667 cycles, against 192,713 with the patched crate | [docs] |
| | ed25519 | 615,819 cycles, of which SHA-512 217,783 | [2nd] |
| Airbender (M31) | BLAKE2s round delegation | 890 columns | [src] |
| | u256 op delegation | 356 columns, u16 limbs, no modular reduction | [src] |
| | zksync-os pricing | P-256 at 500k cycles + 71k delegations (constants, not measured) | [src] |
| OpenVM | 8-bit-limb mod-builder | `SHA256_UPDATE` 17 rows per block, `SHA512_UPDATE` 21 | [src] |
| Longfellow (Ligero + sumcheck over F_p256, hash-based) | ECDSA P-256, single thread | **53 ms on Pixel 9, 31 ms on iPhone 15 Plus**; SHA-256 22 / 12.8 ms per block; emulating P-256 costs "40–100×" | [paper] |

**P-256's field on M31** [modelled]. 32 × 8-bit limbs (SP1's choice; our
Range256 table): the convolution peaks near 2^21, ample headroom; one modular op
a·b − q·m − r = (x − 2^8)·w(x) is about 126 main columns and 126 range lookups.
22 × 12-bit limbs: about 86 columns, a 4,096-row table, a convolution near
2^29.5 < 2^31 (tight). 16-bit limbs overflow M31 in one product. P-256's Solinas
form allows folds like Ristretto's ×38, but ECDSA also needs arithmetic mod n,
which is not special: **one generic q·m gadget for p and n** is simpler.

**What the Ristretto chips teach** [read, `P/src/chips/ristretto/{mod.rs,DESIGN.md}`]:
one GF(2^255−19) op per row at 2,366 columns, of which 1,476 are interaction
columns for 642 Range256 lookups, so the width is the range checks of a
byte-limb two-pass fold, not the data. 16 rows per double, 18 per add;
4,150–6,400 rows per variable-base scalar mult, 1,408 per fixed-base comb (64
windows × 22); 0.75 ms per op on x86 (R1f). Lessons: fewer lookups per op (q·m
needs about 5× fewer), fixed-base tables, shapes per kernel (8 idle 16-row chips
were 42% of the verifier's columns), chain-path memory handlers (flat-only
today), and a `derive` allowance.

**Chips against software** [modelled; interaction ≈ main]:

| chip | rows | columns | cells per operation | software | gain |
|---|---|---|---|---|---|
| SHA-256 (round per row + schedule) | about 64 + 48 per block | about 250–450 | 50–100k | 7.6M | 75–150× |
| SHA-512 | about 80 + 64 per block | about 500–900 | 100–200k | 11M | 55–110× |
| P-256 q·m field op | about 8,000–8,500 per verify (Shamir, a = −3 Jacobian double and add about 18 ops each, plus s⁻¹ and Z⁻¹); w-NAF keeps it within 2^13 | about 420 | about 3.4M (19M at Ristretto width; 39M if it spills to 2^14) | 6.5G | about 1,900× |
| P-256 point-op row (SP1-style) | about 450 per verify | about 2,900 | about 1.6M with the mod-n ops | 6.5G | about 4,000× |
| ed25519 on today's Ristretto chips | 6,400 + 1,408 + about 530 (two decompressions) | 2,366 / 1,216 | about 18M | 1.27G (curve) | about 70× |
| ed25519 on a q·m field row | the same | about 420 | about 3.5–4M | 1.27G | about 330× |

**A statement on chips** [modelled] = glue CPU (about 3k steps of decoding,
JSON and base64 checks and calls, ≈5M cells) + chips + tables (about 1M):
passkey (5 SHA-256 blocks + P-256) ≈ **8–10M cells**; ed25519 (2 SHA-512 blocks
+ curve) ≈ **10M** on a tight field chip, **25M** on Ristretto-width rows.
Software SHA-512 alone is about 22M cells, more than the whole chip budget. It
needs new ECALLs (Edwards double-scalar mult and decompress; P-256 verify or
point ops; SHA-256 and SHA-512 compress), sparse-memory handlers, and `derive`
admitting them.

## 5. Phone translation

**Sources:**

| source | what | tag |
|---|---|---|
| roadmap | x86 reference log14 MOBILE 1.7 s and 1.3 GiB (older code); flagship estimate 3.5–7 s from 0.86 s (×4–8), composed, not measured | [read] |
| `mobile_bench 14` today | 0.73 s on 10 threads, 0.93 s on 4, 1.2 GiB | [measured] |
| FibRace (Stwo / Cairo M; 2.2M proofs, 1,420 device models) | median **6.37 s** for traces of 8–800k cycles; A19 Pro and M1–M4 ≤ 3 s; A18 Pro on par with top Qualcomm; 3 GB RAM floor; 88–96 bits | [paper] |
| csp-benchmarks (Stwo VMs, M1, 8 cores) | about 1.2–1.8 s fixed, 1.8–2.6 GB, even for 128-byte SHA-256: our boundary-laden fixed cost | [src] |
| per-core ARM | Stwo single-thread on Graviton4 1.9× slower than on C7i (AVX-512), 1.22× multi-thread | [docs] |
| | `PackedM31` = u32x16: 4 NEON registers against 2 AVX2 | [src] |
| | Longfellow single-thread: A16 ≈ Zen 4 on a 64-bit NTT; Tensor G4 1.4× slower | [paper] |

**Geekbench 6 multi-core** [2nd]: 155H about 12.3k; Snapdragon 8 Elite 9.8k;
A18 Pro 8.5k; A17 Pro 7.2–7.9k; Snapdragon 8 Gen 3 6.8k; Tensor G4 4.55k; G3
4.1–4.4k.

**The factor** [projected]: a phone's time is our 4-P-core pinned time × 1.0–1.5
(A17 Pro, A18 Pro, Snapdragon 8 Elite: four 155H P-cores score about A17 Pro's
multi-core, up to ×1.5 for NEON's half-width lanes), × 1.1–1.7 (Snapdragon 8 Gen
3), × 1.8–2.6 (Tensor G3/G4). Thermal limits matter little for a 1-second burst;
LPDDR5X bandwidth (about 60–77 GB/s, against about 120 GB/s here) is inside the
range. None of this is measured on a device.

**qemu-aarch64** [measured]: `auth` cross-built (`aarch64-unknown-linux-gnu`,
nightly-2025-07-14), proved in 43 s on 4 emulated threads (meaningless) and
verified in-process. **Its postcard proof is byte-identical to x86's** (SHA-256
`0fb8b627…`; `R/qemu-arm.log`, `R/x86-ref.log`): the NEON/portable-SIMD path
computes the same proof on our 22-chip AIR.

## 6. The verdict per statement

All phone figures [projected]: the 4-P-core time × the phone factor, masked
×1.7, Blake2s, blowup 2 / 76 queries, 96 conjectured bits.

| statement | as built, masked | floor, masked | with the levers | levers needed | residual risk |
|---|---|---|---|---|---|
| auth | 2.9–7.5 s; about 3.5 GiB, **over the cap** | 1.2–3.1 s; 1.5 GiB | levers 2–5: 0.36–0.6 s on x86 → **0.36–0.9 s (Apple), 0.65–1.6 s (Tensor)**; proof about 1–2 MB | 2, 3, 4 and 5 (or 5'); PoW 20 → 10 bits with 86 queries (−30–60 ms on a phone); a core-weighted split | (c)'s real factor on our chips (5.3); no device run; the masked 2^11 floor (+0.07 s); the lean-kernel estimate |
| pay | as auth | as auth | as auth (one more compression; the comparison is free) | as auth | as auth |
| ed25519 | minutes | 27 × 1.03 s, about 47 s masked → 47–120 s | 10M cells → **0.4–0.6 s (Apple), 0.7–1.1 s (Tensor)**; on Ristretto rows 0.9–1.35 / 1.6–2.3 s | Edwards ECALLs (ideally a q·m field row); a SHA-512 chip | 2–3 soundness-critical chips to build and audit; derive and tracer support; masking chips with 600+ lookups per row |
| passkey | minutes | about 4 min masked → 4–10 min | 8–10M cells → **0.4–0.6 s (Apple), 0.7–1.1 s (Tensor)**; at Ristretto width (about 45M) 1.6–2.4 / 2.8–4.1 s | a non-native P-256 chip (point-op rows, or q·m rows with w-NAF), mod-n, SHA-256; glue kept to about 3k steps | the largest build (2–4 chips); non-native range-check soundness. Longfellow does it in 31–53 ms, but it is not a STARK and our recursion cannot fold it |

**Overall.** With masking, nothing is sub-second until single-segment device
kernels drop the page boundary, kernels are lean, BLAKE2b is narrow (or a path or
Poseidon2 primitive exists), and the signatures get precompile chips. Then all
four project to about **0.4–0.9 s on Apple-class and Snapdragon 8 Elite phones**
and **0.7–1.6 s on Tensor G3/G4**; the masked floor of any kernel is about
0.17–0.45 s. (c) at blowup 2 keeps spike 2's caveat: these proofs stay inside a
space, and settlement proofs are re-proved at blowup 8 by a node.

## 7. Reproduce and caveats

```sh
cd spikes/s5-mobile
(cd guest && cargo build --release --target riscv64em-vos.json)
(cd harness && cargo build --release && cargo build --release --features p2 --target-dir target-p2)
harness/target/release/s5-mobile gen 1000000 data
harness/target/release/s5-mobile trace guest/target/riscv64em-vos/release/device-statements.elf auth data/auth.args 32768 8
scripts/run.sh <log> auth 32768 8 S5_REPS=5 RAYON_NUM_THREADS=4                      # as built, verified
scripts/run.sh <log> auth 32768 8 S5_DROP=boundary S5_SPIKE_TOUCHED_BYTES=1          # floor proxy
S5_CPUS=1,3,6,8 scripts/run.sh <log> auth 32768 8 RAYON_NUM_THREADS=4                # 4 P-cores
python3 scripts/best.py
```

The passes: `scripts/{matrix,phase2,phase3,clean,quiet,cores}.sh`. qemu: the
harness built `--target aarch64-unknown-linux-gnu --target-dir target-arm`, run
under `qemu-aarch64 -L /usr/aarch64-linux-gnu`; it needed `rustup target add
aarch64-unknown-linux-gnu --toolchain nightly-2025-07-14`.

**Caveats.** The floor proxies are unverifiable by construction and omit the
small preprocessed data table a real boundary-free shape needs. The `S5_PLUS=1`
runs (`m-c*`) padded only the forcing-set chips; they are not a masking proxy
and are not used. External figures come from the delegated read; "[2nd]" ones,
Geekbench included, were not checked first-hand.
