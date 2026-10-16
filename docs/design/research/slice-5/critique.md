# Slice 5 critique: the proving architecture's assumptions, and where Stwo can be bent to our use

Date 2026-10-16. Read-only on every repository; nothing pushed. Inputs: the plan
(draft 6), audit.md, spike1–3, masking-review.md, context.md, the mobile roadmap,
`pvm/proof` (vos-core and vos-master), the Stwo fork at `e1286720` (+ the
`zk-masking-spike` branch), `starkware-libs/proving` at `916aefb5`, and a web
survey of competing systems (delegated; every external claim below is tagged
**[sourced]** with a link or **[memory]**). Two small measurements were made on
vos-master's prover under `MemoryMax=12G` (§0.1). Tags: **[measured]** here or in
the spikes, **[read]** in source, **[projected]**, **[memory]**.

Paths: `VC` = `/home/daniel/src/virto/vos/.worktrees/vos-core`, `P` = `VC/pvm/proof`,
`S` = `~/src/virto/stwo/crates`, `U` = `tmp/s5/proving-src`.

## 0. Verdicts in one screen

| Owner's assumption | Verdict |
|---|---|
| "Stwo is the state of the art for STARKs" | **Half right.** It is the best-engineered circle-STARK/M31 FRI prover and the only M31 system with a production recursion tree (stwo-circuits). It is not the fastest RISC-V prover in 2026 (Airbender, SP1 Hypercube, ZisK/Pico contest that, all hash-based too), it has no field-native hash channel, no ZK mode, no low-memory mode, and its GKR logup is not wired into the framework. **Keep it for slice 5**; a switch costs 4–9 months and buys nothing the recursion plan needs. Revisit only if the base layer is ever re-architected around sumcheck (§1). |
| "No trusted setup and PQ readiness are musts" | **Accepted, with two corrections.** (i) The PQ claim is inconsistent with the mobile statement: tap-to-pay proves a Schnorr/Ristretto signature, which a quantum computer breaks regardless of the STARK. (ii) 96 *conjectured* bits is ~58 *proven* bits and ~48 bits against a Grover-equipped forger; privacy (hiding) must hold for decades, soundness only until verification. Targets in §2. |
| "A PVM derived from RISC-V E is simpler and faster for a zkVM" | **Not supported, and the data points the other way.** 64-bit values cost 8 byte-limbs per operand (RV32: 4), byte-granular memory costs 8 ledger rows per 64-bit access (word-granular zkVMs: 1), the PVM has ~140 opcodes to RV32IM's ~47 (191 flag columns in CPU), and 13 registers add spills (= more steps) while saving nothing in the AIR, where the register file is a ledger. The PVM's real purchase is JAM alignment, which is decisive and sufficient. "Faster than competing zkVMs" needs word memory, opcode-family components and a lighter page boundary just to reach parity (§3). |
| The design (draft 6) | **Right venue (recursion), right channels, right order; three things to add before 5.1:** a no-boundary single-segment shape; a dedicated Poseidon2-M31 credential/balance AIR for the mobile statements (the zkPVM floor alone is 0.4 s / 0.6 GiB on x86, so sub-second masked on a phone is unreachable through it); and a Poseidon2 root kind for maps read by device proofs. In-proof ES256/Ed25519 is 20–25M cells each: seconds on a phone and not PQ; derive the credential secret through the passkey (WebAuthn PRF) instead (§4.1.1). |
| The recursion plan's feasibility | **Feasible on the circuit stack; the 2–6 month estimate is credible only if the inner proof is narrowed first.** The fold cost is columns × queries of the inner proof; with a Blake2s inner channel our 7.5k-column kernel costs ~6× its own proving to verify in-circuit (§6, R1). |

### 0.1 Fresh measurements (vos-master prover, 16 always-on chips, x86, 10 threads, loaded box)

Add-only program, `prove_profiled_with_config`, harness outside the repos:

| steps | config | prove | peak RSS | proof (postcard) | trace | main commit | interaction | FRI/quotients | log sizes (CPU, BLAKE2B_BOUNDARY, MEMORY, REG_MEM, PROG_MEM, AND_BYTE) |
|---|---|---|---|---|---|---|---|---|---|
| 2^12 | MOBILE | 0.44 s | 616 MiB | 823 KB | 11% | 20% | 19% | 48% | 13, **13**, 14, 14, 14, 16 |
| 2^14 | MOBILE | 0.82 s | 1,173 MiB | 819 KB | 12% | 28% | 16% | 41% | 15, **13**, 14, 16, 16, 16 |
| 2^14 | STANDARD | 1.70 s | 3,685 MiB | 482 KB | 6% | 44% | 17% | 28% | same |
| 2^16 | MOBILE | 2.53 s | 3,786 MiB | 860 KB | 14% | 33% | 17% | 35% | 17, 13, 14, 18, 18, 16 |

(`mobile_bench 14`: 0.70 s / 1.20 GiB; the roadmap's 1.72 s was a 2025 box.) Read: the
single-proof floor is ~0.4 s and ~0.6 GiB **before the program does anything**;
BLAKE2B_BOUNDARY is forced to 2^13 rows (11.7M cells) for a 64 KiB add program and
is ~half the cells at 2^12 steps; FRI/quotients are 35–48% of time at blowup 4
and the Blake2s Merkle commit is 20–44%; STANDARD is 3× the memory of MOBILE.
The 3 GB phone budget binds between 2^14 and 2^16 steps unmasked, so ≤2^14 masked.

## 1. "Stwo is the state of the art" — the field in 2026

### 1.1 The comparison

| system | base | prover speed | mobile | recursion | verifier / proof | PQ end to end | security accounting |
|---|---|---|---|---|---|---|---|
| **Stwo / S-two** | circle STARK, M31, FRI, Blake2s | CPU only: ~0.55M Cairo cycles/s on a 48-thread EPYC (Fib 4.2M cycles in 61 s, 72 GB) **[sourced]** https://docs.starknet.io/learn/S-two-book/benchmarks.md ; no GPU backend | the only large phone dataset, via Cairo-M/FibRace: 2.2M proofs, 1,420 devices, 3–10 s for ≤800k cycles, median ~10 kHz, ≥3 GB floor **[sourced]** https://arxiv.org/pdf/2510.14693 | production: stwo-circuits 2-to-1 tree + Cairo verifier on L1, **no SNARK wrap** **[read]** `U/crates/stark_verifier`, `circuit_multiverifier` | hundreds of KB; L1 Solidity verifier | **yes** (hash only) | 96 **conjectured** (blowup 1, 70 q, 26 PoW) ≈ 55–61 proven **[sourced]** https://github.com/starkware-libs/stwo-cairo |
| **SP1 Hypercube** (Plonky3 lineage) | sumcheck + LogUp-GKR + jagged PCS over FRI, KoalaBear | 99.7% of mainnet blocks <12 s on 16×RTX 5090 **[sourced, vendor]** https://blog.succinct.xyz/sp1-hypercube-is-now-live-on-mainnet/ | none | mature; shrink/wrap → Groth16/PLONK over BN254 | 529–887 KiB STARK, 260 B wrapped | no (EC wrap) | **100 proven (UDR)**: blowup 4, 124 queries **[sourced]** https://docs.succinct.xyz/docs/sp1/security/security-model |
| **OpenVM 2** (Plonky3) | BabyBear, SWIRL + WHIR | 19.4 MHz CoreMark on one 5090; p99 7.9 s on 16×5090 **[sourced, vendor]** https://axiom.xyz/blog/openvm-2-beta | none | native recursion VM → Halo2/KZG | <300 KB | no | 100 proven **[sourced]** https://github.com/ethereum/soundcalc/blob/main/reports/summary.md |
| **Airbender** | M31, RV32IM, DEEP-FRI, Blake2s/3 | 21.8 MHz on one H100 **[sourced, vendor 2025]** https://zksync.io/airbender | none | pairwise → FFLONK/BN254 | n/p | no | "81 bits initial" **[sourced]** https://l2beat.com/zk-catalog/airbender ; absent from soundcalc's ≥100 table |
| **RISC Zero** | BabyBear, DEEP-ALI FRI | 1.1 MHz/H100 (2025) | none; 3 GB guest | lift/join/resolve → Groth16 | ~200 KB / 256 B | no | 96–99 conjectured ("toy problem") **[sourced]** https://dev.risczero.com/api/security-model |
| **Jolt** | sumcheck + lookups; Dory (EC) or **Akita lattice** PCS | CPU laptop >2M RV64 cycles/s; 10M with Metal **[sourced, vendor]** https://a16zcrypto.com/posts/article/lattice-snarks-jolt-post-quantum-faster/ | 6–50 GB RAM in 2025 benches; phones claimed, no numbers | **roadmap only**; no on-chain verifier | 61–80 KB | Dory no; Akita yes (lattice, not hash) | 128 target; alpha |
| **Binius / Binius64** | binary towers | ECDSA sign 0.56 s x86 | — | never shipped | 188 KiB, non-succinct verifier | yes | company shut down Nov 2025 **[sourced]** https://www.irreducible.com/ ; beyond-Johnson gaps over binary fields refuted Oct 2026 https://eprint.iacr.org/2026/2424 |
| **WHIR / STIR / BaseFold** | PCS, not VMs | WHIR 2^22: 1.2 s commit+open, 63 KiB **[sourced]** https://eprint.iacr.org/2024/1586 ; STIR 114 KiB vs FRI 211 KiB at 2^26 https://eprint.iacr.org/2024/390 | — | — | 2–3× smaller proofs than FRI | yes | proven at Johnson (Bordage et al. 2025/2051) |

### 1.2 Reading it for us

- **Stwo is the right base for a hash-only, PQ-consistent, phone-capable stack**: it
  is the only production zkVM stack verified on L1 without an EC wrap, and the only
  one with a phone dataset. Its weaknesses are exactly the ones this plan hits: no
  GPU, no low-memory mode, CPU throughput 10–40× below GPU zkVMs, no ZK, no
  field-native hash channel, GKR unwired.
- **"State of the art" for raw RISC-V throughput is Airbender/OpenVM/ZisK on GPUs**
  (10–22 MHz per card), i.e. 3–4 orders of magnitude above our 6–20 kHz CPU
  figures and FibRace's phone median. Our node provers can only compete on cells
  per step, not on hardware, until a GPU backend exists (icicle-stwo is stale, roadmap).
- **The frontier moved to proven security.** The EF requires 100 proven bits now
  and 128 by end-2026, proof ≤ 300 KiB, no trusted-setup wrapper
  **[sourced]** https://blog.ethereum.org/2025/12/18/zkevm-security-foundations ;
  soundcalc dropped the capacity regime after Diamond–Gruen (2025/2010) and
  Crites–Stewart (2025/2046) refuted the up-to-capacity conjecture as stated
  **[sourced]** https://blog.zksecurity.xyz/posts/proximity-conjecture/ . The
  salvage (fixed-rate, entropy-corrected) conjecture costs +3–15% queries; moving
  to proven Johnson/UDR costs ~2× proof size and verifier time with the prover
  roughly unchanged. StarkWare's S-two whitepaper (2026/532) proves only to Johnson
  **[sourced]** https://eprint.iacr.org/2026/532 . **Our 96 conjectured bits are
  industry-normal and below the new bar**; §2 sizes the layers accordingly.
- **Security events to learn from:** stwo-cairo's LogUp claimed-sum not absorbed into
  Fiat–Shamir (Jun 2026) **[sourced]** https://axiom.xyz/blog/stwo-bug ; SP1 V6
  recursive verifier CVE-2026-40323. Both are in exactly the code we will write
  (claimed sums, in-circuit verifier): budget an external audit of the fold.
- **Switching cost:** §7. None of the alternatives shortens slice 5.

## 2. Security level under "no trusted setup, PQ"

- **What 96 bits means here.** `conjectured_security_bits = pow_bits + n_queries ·
  log_blowup` (`P/src/proof.rs:1099-1110`; Stwo's own `FriConfig::security_bits`,
  `S/stwo/src/core/fri.rs:77-79`, has no proven-regime formula). This counts one bit
  per query per blowup bit, i.e. list decoding up to capacity (the ethSTARK
  "up-to-capacity" conjecture). **Proven (Johnson) bits are half the FRI term:**
  STANDARD 20 + 19·2 = 58, MOBILE 20 + 38·1 = 58 (Fable, masking-review §2.1).
  Whether the capacity conjecture survives is answered in §1.2: refuted as stated (2025),
  salvage unproven; stwo-cairo itself ships blowup 1 / 70 queries / 26 PoW
  (`U/circuit_registry_definitions/production/cairo_prover_params.json`), the same
  96 conjectured bits, so we are at industry practice, not above it.
- **Grover.** A hash-based STARK has no algebraic structure a quantum computer
  breaks, but the Fiat–Shamir compilation is a search: finding a transcript whose
  queries miss the cheat is a 2^(q·b) classical search, ~2^(q·b/2) with Grover,
  and PoW bits halve the same way (Don–Fehr–Majenz–Schaffner QROM results give a
  quadratic loss for FS of round-by-round-sound IOPs; CMS19 for Kilian) **[memory;
  §1.2 and §9 of the survey for sources]**. So **96 conjectured ≈ 48 quantum bits**, 128 ≈ 64.
  Hash sizes: Blake2s-256 collision 128 → ~85 (BHT, impractical memory) and
  preimage 256 → 128; Poseidon2-M31 digests of 8 M31 (248 bits) likewise. The
  M31 field itself is fine: QM31 ≈ 2^124 makes the Schwartz–Zippel terms ~2^-100.
- **Soundness is short-lived, hiding is long-lived.** A forged payment proof must be
  forged before it is verified; a leaked ledger is leaked forever. So:
  - **soundness:** 100 conjectured / ≥60 proven bits is acceptable today for inner
    and final proofs, with the format recording both (Fable gate 10) and the final
    layer sized so a later move to 128 conjectured costs only queries;
  - **hiding:** salts must resist Grover preimage for decades: spike 2's 4 M31
    (124 bits) becomes 62 quantum bits. **Use 8 M31 salts (248 bits)**; cost is
    4 more columns per salted tree. The polynomial masks are information-theoretic
    and need nothing.
- **What it implies per layer.**
  - **Mobile (device) proofs:** blowup 2 / 76 queries is the only shape that fits
    memory, and it has no slack beyond the capacity conjecture (Fable would not
    publish settlement proofs at it). Acceptable for an authorization that a
    space re-checks and whose exposure is one payment; not for a settlement.
  - **Fold layer:** inner proofs are verified only by our recursion, but their
    soundness is load-bearing for outsiders (a 2^58 inner forgery is a 2^58 final
    forgery). Use ≥ 100 conjectured bits with blowup ≥ 4 (log 2) and 26 PoW, plus
    stwo-cairo's 24-bit interaction PoW before the logup challenges
    (`U/crates/cairo-air/src/verifier.rs:248`), which vos-core lacks and which is
    the cheapest soundness lever for a 32-relation logup.
  - **Final layer:** a ~400-column AIR can afford the proven regime: Blake2s channel,
    blowup 2^6–2^8, 16–25 queries, 26–30 PoW (one grind per statement; 2^30 Blake2s
    compressions ≈ seconds on SIMD, `S/stwo/src/prover/backend/simd/grind.rs:61-130`),
    fold_step 4 with packed leaves (`S/stwo/src/prover/fri.rs:295-302`). Target
    ≥ 100 conjectured and ≥ 80 proven, pinned in the format.
- **The PQ inconsistency.** Tap-to-pay (`clerk-private-pay-bench`: Pedersen commit +
  Schnorr on Ristretto, `vos-master/pvm/proof/benches/actors.rs:359`) proves a
  statement whose security is discrete-log. If PQ is a must, the mobile statement
  must be hash-based (Poseidon2-M31 Merkle membership + nullifier + binding to the
  payment, as the identity design's §8 shielded pool already implies), which is
  also 10–50× cheaper to prove (§4.1).

## 3. "A PVM from RISC-V E is simpler and faster for a zkVM"

- **The ISA's share of the AIR is small.** CPU is 781 of 13,037 columns (6%), 708
  constraints (`audit.md` §1.1); Ristretto 42%, BLAKE2b 23%, the page boundary 22%.
  For kernels the ISA barely matters; precompiles and the memory model do.
- **64-bit registers cost 2× RV32 in every value column.** `ValB`, `ValD`, `Result`,
  `Carry`, `Gas`, `Timestamp` are 8 limbs each (`P/src/chips/cpu/columns.rs:14-58`);
  SP1's RV32 word is 4 bytes **[memory]**, Airbender uses 16-bit limbs over M31
  **[memory; survey]**. Byte limbs are forced by XOR/AND via byte tables; a 64-bit
  design needs 8 of them, RV32 4. MUL (166 cols) and DIVREM (249) are 64×64
  products with 16-limb carries: roughly 3–4× an RV32 mul chip.
- **Byte-granular memory is the larger ISA-adjacent cost.** One `MemoryAccess` lookup
  per byte (`audit.md` §1.4): a 64-bit load is 8 ledger rows; MEMORY runs at 2^18
  rows for 32k steps (8 per step). Word-granular memory with a byte-select column
  (what RISC Zero and SP1 do **[memory]**) cuts the ledger 4–8× and the page
  boundary's 8,192 entries per page to 512. This is the single ISA-level change
  with the best ratio.
- **"E" helps the interpreter, not the AIR.** The register file is a ledger
  (REGISTER_MEMORY, 93 cols, 4 rows per step, 2^17 at 32k: `audit.md` §1.4), so
  its width is independent of the register count. Fewer registers mean more
  spills, and each spill is a byte-granular memory access. The window kernel runs
  593 steps per compression against a ~170-step floor (spike 3 §3.3), partly for
  this reason. Verdict: **neutral to negative** for the zkVM.
- **~140 opcodes vs RV32IM's ~47.** `vos-pvm`'s `Opcode` enum has 140 variants
  (`VC/pvm/runtime/src/instruction.rs:10`): 32- and 64-bit forms, immediate and
  "alt" forms, cmov, rotates, min/max, bit counts. The CPU chip pays one boolean
  flag column per form (191 of 601 main columns) and one constraint set per form on
  every row, whatever the row executes. RV32IM zkVMs that are fast split the CPU
  into opcode-family components so a row costs only its family (stwo-cairo's
  opcode components; SP1's ALU/memory/branch chips **[memory]**). The PVM's richer
  ISA is a reason to do that sooner, not a saving.
- **What the PVM does buy:** JAM alignment (the agent *is* a JAM program, so no
  second toolchain or semantics gap; non-negotiable), no compressed instructions
  or CSRs, a static jump table and basic blocks (JUMP_TABLE is 13 columns,
  PROGRAM_BOUNDARY 29), and `NextPc = pc + 1 + skip_len` (3 carry columns).
  Variable-length byte coding costs a per-byte PROGRAM_MEMORY table (37 cols at
  2^16) that fixed-width RV32 avoids — a wash.
- **Throughput today.** 32k-step kernel segment: 5 s b2s / 23 s p2 at MOBILE
  (audit §2.3) ≈ 6.5 kHz / 1.4 kHz including 378 boundary compressions; add-only
  2^14 steps in 0.82 s ≈ 20 kHz (§0.1). Competitors' RV32 CPU figures are in
  §1.1; the gap is one to two orders of magnitude on servers and a factor of a few
  on the cheap-step mix. **"Faster" is not plausible as built**; parity is, after
  word memory, opcode families, a lighter boundary and narrow BLAKE2b.

## 4. What to change, ranked by impact over effort

### 4.1 Mobile: sub-second small statements under 3 GB

| # | change | impact | effort | basis |
|---|---|---|---|---|
| 1 | **A fixed credential AIR for authentication and payment authorization** (Poseidon2-M31 Merkle membership + nullifier + binding to the payment/challenge, masked), on the existing PCS plumbing; the zkPVM stays for general kernels | ~50 columns × 2^10–2^12 rows: tens of ms, <100 MiB, PQ-consistent; vs ≥0.4 s / 0.6 GiB floor + Ristretto chips (2,366 cols × 2^15+ rows for a Schnorr check) | 3–6 weeks incl. masking | §0.1; audit §1.4; identity §8 already names it |
| 2 | **A no-boundary single-segment shape**: drop BLAKE2B_BOUNDARY, MEMORY_PAGE, MEMORY_MERKLE, MEMORY_ROOT_BOUNDARY when a statement is one segment; bind the initial image by a preprocessed/public commitment and the result by the io-hash; MEMORY's `ts=0` entries bound to the image, not to a page root | −2,787 of the 3,957 floor columns; ~−50% cells at 2^12 steps, ~−25% at 2^14; proof −30–40% | 2–4 weeks (a verifier variant, image binding, shape pin) | §0.1 log sizes; audit §1.1 |
| 3 | **Masking (c) at blowup 2 / 76 queries, budget ≤ 2^14 steps per device proof** | ×1.6–1.7 memory → ~2 GiB at 2^14; fits | design only | spike 2 §3b |
| 4 | `store_polynomials_coefficients` off on phones | coefficients are LDE/2^b: −20% of LDE memory at blowup 4; OODS eval slower (barycentric) — measure | hours | `S/stwo/src/prover/pcs/mod.rs:71-73`, `component_prover.rs:52-66` |
| 5 | Cap rayon at 4–8 on phones; retune the two x86-measured SIMD constants | LPDDR bandwidth; transient buffers | days | `S/stwo/src/prover/backend/simd/mod.rs:47-50`, `quotients.rs:89,215` |
| 6 | Blake2s, not Poseidon2, for device proofs; verified directly by the space/pool, not folded | Poseidon2 channel is 2.8–8.9× prove time on CPU (spike 3 §3.2) | decision | |

#### 4.1.1 The owner's three mobile statements (2023+ flagship, <3 GB, sub-second, masked)

Scale: FibRace puts a flagship at ~3 s for ~2^17 Cairo-M cycles and ≥3 GB; our x86
floor is 0.4 s / 0.6 GiB at 2^12 steps (§0.1), a phone is 4–8× slower per the
roadmap's own estimate, and masking (c) is ×1.6–1.7. **Sub-second masked is out of
reach for anything that goes through the 16-chip zkPVM floor**; it is in reach
for a dedicated AIR of ≤ ~5M cells.

| statement | what it needs in-circuit | zkPVM today | dedicated AIR | fits sub-second masked? |
|---|---|---|---|---|
| (1) authentication: Merkle membership + nullifier | ~32 hash compressions (depth 20–32) + 2 for leaf/nullifier | BLAKE2b tree: 34 × 96 rows × 2,981 cols ≈ 10M cells + the floor; 2–4 s phone | Poseidon2-M31 tree: 34 permutations ≈ 34 rows × ~160 cols; <0.1M cells; **tens of ms** | **yes, dedicated AIR with a Poseidon2 root kind**; no with the zkPVM |
| (2) private payment authorization: committed-row read + balance ≥ amount | one vos-tree multiproof (≈21 compressions per row at 10^6 rows, spike 3) + a 64-bit range check + binding to the payment | as (1) plus the kernel's ~12,700 steps per row read (spike 3 §3.3): 2^14 steps → 1.2 GiB unmasked, ~2 GiB masked, 3–6 s phone | if the balance map has a Poseidon2 root kind: ~25 permutations + 8 byte lookups: <0.2M cells, **<0.1 s**; with the BLAKE2b tree: ~2M cells, ~0.3–0.6 s phone | **yes with Poseidon2 maps; marginal with BLAKE2b** |
| (3a) passkey ES256 in-proof: P-256 ECDSA + SHA-256 | 2 scalar mults (one variable-base) ≈ 8k field ops mod p256 + an inverse mod n256 + 2–4 SHA-256 compressions | nothing exists: new P-256 field chip (byte or 9-bit limbs, ~2,400 cols like Ristretto), point driver, SHA-256 chip (~64 rows × ~700 cols per block) | same chips as a dedicated AIR: ≈ 2^13 rows × 2,400 cols ≈ **20–25M cells** → ~0.5 GiB and ~0.5 s x86, **2–5 s phone**, ×1.7 masked | **no** |
| (3b) Ed25519 in-proof: SHA-512 + Edwards25519 | 1 fixed-base (comb chip exists) + 1 variable-base scalar mult (~6,500 rows × 2,366 cols ≈ 15M cells) + point decompression (sqrt ≈ 250 field muls) + 2 SHA-512 compressions (new chip, BLAKE2b-like width) | Ristretto field chip reusable; SHA-512 and an Edwards point driver new | ≈ **18–22M cells**: 2–4 s phone, ×1.7 masked | **no** |

- **Non-native 256-bit fields on M31.** Byte limbs (Ristretto today: 32 limbs, 64-limb
  products, 642 `Range256` lookups per row) or 9-bit limbs (29 limbs; stwo-cairo's
  felt252 pattern with `range_check_9_9` **[memory]**): products of 15-bit limbs
  already overflow M31 when summed, so limbs stay ≤ 9–10 bits and a 256-bit field
  op is one ~2,400-column row whatever the modulus. Build **one generic
  bignum-mod-p chip** with the modulus in preprocessed columns (p25519, p256,
  n256 are three moduli; ECDSA needs the scalar-field inverse too) and curve
  drivers on top, rather than one chip per curve. Expect ~10 field ops per point
  op and ~6k–8k field ops per verification whatever the curve; the width, not the
  algorithm, is the cost. A GLV endomorphism helps secp256k1, not P-256.
- **Hash chips.** SHA-256 is 32-bit (4 byte limbs): about half BLAKE2b's width,
  64 rows per block; SHA-512 is BLAKE2b-shaped (64-bit, 80 rounds). Both need the
  narrow-chip layout from the start (I/O rows separate from round rows), or they
  repeat BLAKE2b's 50%-waste.
- **The design answer for (3): keep the signature outside the proof unless anonymity
  needs it inside, and derive the credential secret through the passkey instead of
  verifying the passkey in-circuit.** The authenticator signs natively over a
  challenge that commits to the proof's public inputs (zero in-circuit cost) when
  the key may be revealed. When it must stay hidden, use WebAuthn's PRF /
  `hmac-secret` extension **[memory: shipped in iOS/Android/Chrome 2024]** to derive
  a device-bound secret, and make the credential leaf `Poseidon2(secret ‖ …)`: the
  proof is statement (1), the passkey is the UX and the key wrap, and the whole
  thing is PQ-consistent, which an in-circuit ES256/Ed25519 never is. In-proof
  Ed25519 belongs to node-side proofs (verifying others' signatures inside a
  kernel), where seconds are fine and the Ristretto chip already pays most of it.
- **What this changes in the plan:** 5.1 should add a Poseidon2-M31 root kind for
  maps read by device proofs (vos-tree's hasher moves to the compress level
  anyway, 5.2), and the dedicated mobile AIR becomes a slice item rather than the
  identity design's deferred note. The separate baseline (`tmp/s5/mobile.md`) will
  put x86 numbers on the rows above; the orders of magnitude will not move.

### 4.2 Node throughput, up to the fold

| # | change | impact | effort | basis |
|---|---|---|---|---|
| 1 | **Shape per kernel** (mask from code, pinned with log sizes) | −10% RSS, −14% bytes, −38% verify; halves what the recursion must verify | ~1 week | audit §2 (measured) |
| 2 | **Lighter page boundary**: Poseidon2-M31 page hashing (≈150 rows/page vs 32×96) or **one memory argument across segments** (deletes the four boundary chips, −49% cells at the 32k cut) | the prover's biggest lever; also enables larger segments in the same RAM | 3–5 / 6–10 weeks | audit §4 |
| 3 | **Narrow BLAKE2b chips** (per-compression I/O on its own row; word-level memory binding), stwo-cairo style (scheduler + round + G components) | −2,200 columns; −30–45% of BLAKE2B's cells | 3–5 weeks | audit §1.4; `U/crates/circuits/src/blake.rs:308-328` |
| 4 | **Word-granular memory** (byte-select) | MEMORY ledger 4–8× fewer rows; boundary entries 16× fewer | 4–6 weeks, touches CPU, BLAKE2b, boundary | §3 |
| 5 | **Opcode-family CPU components** | CPU 25.6M of 200M cells at 32k; −50–70% of that; more for verify/recursion (601 → ~100–200 main cols per family) | 6–10 weeks | §3; stwo-cairo |
| 6 | Interaction PoW (24 bits) before logup challenges | soundness, not speed; cheap | days | `U/crates/cairo-air/src/prover.rs:299-300` |
| 7 | Keep all chips at one constraint-degree bound ≤ log_blowup+1 | avoids `ExtendToEvalDomain`, a transient re-LDE of the whole trace | audit only | `S/stwo/src/prover/air/accumulation.rs:22-70` |
| 8 | GKR logup | not wired into the framework (only `examples/xor/gkr_lookups`); skip for this slice | — | `S/constraint-framework/src/lib.rs:41-44` |

### 4.3 Recursion and verification (Kreivo Wasm pallet, then a JAM agent)

| # | change | impact | effort | basis |
|---|---|---|---|---|
| 1 | **Narrow the inner proof before building the fold** (4.2 #1–3): recursion cost ∝ inner columns × queries | 7,519 → ~5,300 → ~2,800 columns: 2–3× cheaper folds | as above | audit §5.2 |
| 2 | **Inner channel decision at spike 4**: Poseidon2-M31 gate in StarkWare's circuit (one permutation ≈ one 160-column row) vs their Blake2s gates (80 G rows per compression) | Blake2s inner: our kernel shape costs ~6× its own proving to verify in-circuit; Poseidon2: ~13% | the gate: weeks | audit §5.2; `U/crates/circuits/src/blake.rs` |
| 3 | **Final layer parameters**: fold_step 4 + packed leaves, last layer 2^5–2^7, blowup 2^6–2^8, Blake2s | cuts the width-free verify part (0.14–0.42B gas today at fold_step 1, `P/src/proof.rs:423`) by an estimated 30–50% | days once the layer exists | `S/stwo/src/prover/fri.rs:132-195`; `U/.claude/rules/stwo-circuits-guide.md:95-115` |
| 4 | **Lean verifier**: no `InfoEvaluator` preflight, components built once, shapes precomputed | −8% gas (audit); more on an 11-component final AIR where decode+preflight is a larger share | 1–2 weeks | spike 1 §4–5 |
| 5 | **Wasm verify of a final-shape proof now** (`P/verifier-wasm-bench` exists): a 319–400-column synthetic AIR at the §2 final parameters | retires the Kreivo weight/size question before the recursion exists | days | |
| 6 | One final shape for every kernel: leaf circuits generated per kernel from its chip mask; fold nodes one shape; kernel id a public input | see R7 | design | |

## 5. Stwo: concrete opportunities, with file:line

- **Prover memory is `4 B · C · 2^(n+b)` for all trees at once**, plus 64 B·T·2^L
  of Merkle layers, held from `commit` to the end of `prove_values`
  (`S/stwo/src/prover/pcs/mod.rs:354-357, 285-293`; `evaluate_polynomials`
  `poly/circle/ops.rs:95-126`). No streaming or low-memory mode exists; the
  mempool (`prover/mempool.rs:14-62`) only recycles between proofs. The lever is
  **C · 2^b**: fewer cells (§4.2) beats any schedule trick, as the roadmap's
  recompute-LDE dead end showed (−9.6% / +75%).
- **The lifted Merkle leaf is a whole row** (`prover/vcs_lifted/prover.rs:34-77,
  113`): 16 M31 per Blake2s compression (`core/vcs_lifted/blake2_merkle.rs:15-36`),
  so a 781-column tree costs ~49 compressions per leaf per query, and a 16-row
  chip lifted to 2^17 costs the verifier as much as a full one. That is why
  "every column costs the verifier the same" (audit §1.3) and why dropping chips
  is the only width lever that helps the verifier.
- **Composition evaluation mode** (`prover/air/accumulation.rs:22-70`): if any
  component's extra constraint degree exceeds `log_blowup`, or differs across
  components, the prover re-LDEs **every** trace column to the composition domain
  (`S/constraint-framework/src/prover/component_prover.rs:45-70`). vos-core is
  uniform at bound 1, so safe; **masking variant (c) lifts to m+2 and must be
  checked against this before 5.4**, or its ×1.6 becomes ×2+ transiently.
- **FRI knobs the format pins shut**: `fold_step` (`core/fri.rs:35`, prover
  `fri.rs:132-195`, packed leaves at `fri.rs:295-302` / `core/vcs_lifted/verifier.rs:14-15`)
  and `log_last_layer_degree_bound ≤ 10` (`core/fri.rs:39-40`). vos-core pins
  fold_step 1 and last layer 0 (`P/src/proof.rs:418-424`); stwo-cairo production
  uses fold_step 4. Free verify-cost lever for the final layer.
- **Security accounting**: only the conjectured count exists (`core/fri.rs:77-79`,
  `core/pcs/mod.rs:44-46`); upstream moved `pow_bits` into `FriConfig` and split
  lifting into trace/preprocessed sizes (`U/crates/stwo/src/core/fri.rs:31-37`,
  `core/pcs/mod.rs:43-55`): expect this drift in the port.
- **Channels**: Blake2s, Blake2sM31 (digests reduced mod p, `core/vcs/blake2_merkle.rs:33-35`),
  Keccak, Poseidon252. **No Poseidon2-M31 hasher exists upstream or in the fork**;
  vos-core's is home-made (`P/src/poseidon2/mod.rs`), 15,850 PVM instructions per
  permutation (spike 1 §5), and stwo-circuits has no Poseidon2 gate. StarkWare
  folds Blake2sM31-channel proofs with Blake gates
  (`U/crates/stwo_run_and_prove_recursive_tree/src/lib.rs:17-22`).
- **Preprocessed tree reuse**: build once, lend by `MaybeOwned::Borrowed`
  (`prover/pcs/mod.rs:93-100`), as stwo-cairo caches it
  (`U/crates/privacy_prove/src/lib.rs:70-80`); vos-core rebuilds per proof (2–4%
  of time, §0.1). Components share preprocessed columns by id
  (`S/constraint-framework/src/preprocessed_columns.rs:1-6`, `component.rs:33-90`).
- **Logup**: `finalize_logup_in_pairs` = one QM31 column per two fractions at +1
  degree (`S/constraint-framework/src/lib.rs:146-250`); the interaction tree is
  4 M31 per batch. Batch-3/4 was a NO-GO for degree (roadmap C3); (c)-masking
  keeps the pairs.
- **SIMD on ARM**: `PackedM31 = u32x16` portable (`backend/simd/m31.rs:18-22`) →
  4 NEON registers; M31 mul uses `vmull/vqdmull` (`m31.rs:183-188, 337-409`);
  `min_u32x16` falls back to portable on non-x86 (`m31.rs:51-54`); Blake2s is
  16-way portable (`simd/blake2s.rs:165-209`). Expect the hash share (20–44% of
  time, §0.1) to rise on ARM; FibRace confirms the envelope.
- **ZK**: nothing in core Stwo, pin or upstream. Upstream's `add_zk_blinding`
  (`U/crates/circuit_common/src/finalize.rs:85-177`) adds `n_queries + 10` random
  rows per circuit component, seeded from the trace root
  (`U/crates/cairo_verifier/src/verify.rs:165-167`): row-level only, witness-seeded
  randomness (Fable's R4 objection). Our fork's recipe (`S/examples/src/zk_masking/`)
  is the complete one.
- **Column-size histogram at prove time** (`prover/pcs/mod.rs:420-434`): use it to
  size C per log size when ranking §4.2.

## 6. Late surprises in the recursion plan, and the measurement that retires each

| # | risk | why it could sink 2–6 months | measure first |
|---|---|---|---|
| R1 | **Fold cost ∝ inner columns × queries**, and StarkWare's circuit hashes Blake2s | our 7,519-col kernel at 26 queries ≈ 12k leaf compressions + paths ≈ 2^22 G-rows of a 319-col AIR ≈ 1.3G cells, ~6× the segment's own 200M; with 70 inner queries, worse | spike 4: gate count for one kernel-shape segment in the circuit stack, both with Blake2s gates and with a Poseidon2 gate estimate; rule: fold ≤ 30% of segment proving |
| R2 | **Masking StarkWare's circuit prover**: their AIR's constraint degrees and `add_zk_blinding` design differ from ours | variant (c) needs degree ≤ 3; a degree-4 gate forces unpairing or (a) at ×2 memory; also `ExtendToEvalDomain` (§5) | `ExprEvaluator` degree audit of the 11 circuit components; one masked circuit proof under (c) |
| R3 | **The monorepo port** (`nightly-2026-01-15`, edition 2024, `PcsConfig`/lifting drift, 46 commits to core) breaks the 32 chips and the pinned format | weeks → months if the lifted-tree semantics changed | the port spike's breakage count (planned); keep the fork's verifier format pinned and diff proofs byte-for-byte |
| R4 | **Inner soundness is load-bearing** (§2): inner proofs at MOBILE are 58 proven bits; moving to ≥ 100 conjectured with blowup 4 costs prover memory 1.7–3× (audit §3) and more queries cost fold time | choose inner params now; model fold cost at (2,38), (3,26), (4,19) | 
| R5 | **Public-input model vs. a later global memory argument**: 5.1's salt page and the initial-image split assume page-Merkle roots; global memory replaces them with blinded sums | a second format change and a second masking review | design 5.1 so no root over private memory reaches a public input (Fable §3); decide 4.2 #2 before 5.1 |
| R6 | **Device proofs must be ZK at the base layer** (confirmed: they leave the device and are verified by a party that must not learn the key/note); (c) at blowup 2 is ×1.6–1.7 memory; tap-to-pay with Ristretto chips (2,366 cols × 2^15–17) does not fit 3 GB masked | the only mobile story would be a server re-prove, which leaks the witness | build the `clerk-private-pay-bench` fixture (absent from both trees) and run the §0.1 profile masked; or adopt 4.1 #1 and measure a 2^12-row Poseidon2 credential AIR masked |
| R7 | **One final shape for every kernel and verifier**: a leaf verifier circuit is specialized to one inner AIR (chip set + log sizes), so a shape per kernel means a generated leaf circuit per kernel and a circuit id per kernel; the fold nodes and the final proof are one shape only if leaves are padded to one circuit shape | if leaves must share one circuit, it is the union of chips, and the per-kernel saving is lost in the fold | spike 4: generate leaf circuits for the window kernel and the solvency predicate; measure their sizes and whether one fold-node shape covers both |
| R8 | **Kreivo pallet limits**: a 100–300 KB proof per extrinsic and a Wasm verify of 16–25 queries × 400 columns at blowup 2^8 | extrinsic size/weight caps may force splitting or a smaller final proof | Wasm bench of a synthetic 400-col proof at §2 parameters (`P/verifier-wasm-bench`), now |
| R9 | **JAM gas**: 60–150M is projected; spike 1's 0.79B fixed floor was for 32 components, the final AIR has ~11, but decode+preflight scale with proof bytes | the 100M rule may fail by 2× | spike 4's go/no-go with the lean verifier (4.3 #4), not today's code |
| R10 | **Fold-proof memory** unmeasured; (c) ×1.6 on top | a fold node above 24 GiB | the first circuit proof's RSS at the inner params of R4 |
| R11 | **Lifted protocol and degree ≥ 2**: the roadmap records "not supported yet in the lifted protocol" for `LOG_CONSTRAINT_DEGREE_BOUND ≥ 2`; (c) needs lifting at m+2 | masking (c) blocked on the fork | confirm on the fork: the spike-2 prototype's (c) tests pass, so likely resolved; pin a test |

## 7. Switching costs, for the record

- **Plonky3 / KoalaBear or M31**: all 32 chips are written against Stwo's
  `EvalAtRow`/logup framework and circle domains; a port is 3–5 months for parity
  and loses stwo-circuits; gains a hiding PCS and a Poseidon2 Merkle out of the
  box. Not worth it for slice 5.
- **Sumcheck/jagged (SP1 Hypercube style)**: width-independent verifier, streaming
  prover, no FRI; a full re-architecture (6–12 months) and no M31 circle tooling.
  The right destination only if the base layer is rebuilt; the recursion plan does
  not need it.
- **Airbender (M31, RV32IM)**: closest field-mate; its ISA is RV32, its recursion
  ends in a SNARK wrapper **[survey]**; not a drop-in for the PVM.
- **Jolt, Binius, WHIR/STIR**: see §1.2–1.3; none ships an M31 or PVM path today.
