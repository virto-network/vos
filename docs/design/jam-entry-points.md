# JAM entry-point convergence (graypaper jump prologue)

Status: DESIGN (decided 2026-07-08: converge toward JAM proper;
adversarially reviewed 2026-07-08 — findings folded in, notably the SP
preamble blocker in §3.1 and the register-ABI scoping in §3.2). Spans two
repos — jar (grey-transpiler, javm, grey-state, Lean spec) and vos
(vos-macros, runtime, A15). Companion: `work-result-contract.md` (the bytes
the accumulate entry consumes).

## 1. The convention to converge on

Graypaper main (claims verified against
`gavofyork/graypaper` `text/{pvm_invocations,accumulation,accounts}.tex`,
fetched 2026-07-08 — pin the exact GP commit when the jar spec change
lands) gives service code exactly **two** entry points, selected by the
**instruction counter** at invocation:

| Invocation | Entry IC | Source |
|---|---|---|
| is-authorized `Ψ_I` | 0 | `Ψ_M(…, 0, …)` — stateless, no host calls |
| refine `Ψ_R` | **0** | `Ψ_M(blob, 0, refgaslimit, args, …)` |
| accumulate `Ψ_A` | **5** | `Ψ_M(blob, 5, g, encode{t, s, len(i)}, …)` |
| on-transfer `Ψ_T` | — | **absent from current graypaper** — accounts.tex names exactly two logical entry points; deferred transfers are integrated as accumulate *inputs* |

So the answer to "2 (3?)" is **2**. jar is already half-aligned on the
transfer question: `Jar.Services.AccumulationInput = operand | transfer` is
exactly the folded model, and `onTransfer` (Ψ_T, `Services.lean:301-317`)
is dead code with zero call sites.

The mechanism: ICs are byte offsets into the PVM code; the convention
expects entering at IC 0 or IC 5 to land on a jump to the respective body
(grey's plain jump = opcode 40 + imm32 = exactly **5 bytes**,
`riscv.rs:1791-1798`, so the two slots pack). This is where VOS's fossil
"accumulate, PC=5" comments came from; the prologue was simply never
emitted.

## 2. Current deviations (both repos)

- **grey-transpiler** (`linker.rs:107-131`): the blob begins with a
  **10-byte SP preamble** (`load_imm_64 φ[1] = stack_top` — jar puts stack
  init *in the blob*; javm deliberately never sets SP,
  `kernel.rs:305-315`), followed by a single jump to the ELF `e_entry`
  (`_start`) at ~IC 10. Nothing at IC 5; entering anywhere but 0 is
  undefined.
- **grey-state** (`accumulate.rs:628-631`): invokes accumulate at **PC 0
  with `φ[7]=1`** as a phase selector — a jar-local convention no other
  JAM implementation understands, and the reason a VOS blob's refine body
  would re-run on accumulate.
- **Register ABI**: jar's kernel passes args as `φ[8]=args_base,
  φ[9]=args_len` (with `φ[7]` as the op selector); GP standard
  initialization passes the argument address/length in **ω_7/ω_8** and the
  **host** sets SP. This deviation is independent of the entry ICs but
  gates real blob portability (§3.2).
- **jar Lean spec**: partially converged already — `Accumulation.lean`'s
  `accone` selects `entryPC = 5` for the gp072 variant
  (`capabilityModel = .none`, the default) and uses PC 0 + `φ[7]=1` only
  for the `.v2` capability-kernel branch (the one grey-state's live Rust
  path implements). `Ψ_R` and the dead `Ψ_T` enter at 0.
- **jar in-tree guests**: `pixels-service` dispatches on `φ[7]` in
  `_start` assembly (`main.rs:44-56`) — it must be ported;
  `counter-service`/`sample-service` already export `refine`/`accumulate`
  symbols and only need rebuilds (which confirms the porting shape).
- **vos**: guest accumulate machinery was unreachable dead code (deleted
  by A0); the host never invokes anything but IC 0.

## 3. Target design

### 3.1 Blob layout (emitted by grey-transpiler)

The prologue slots must be exactly the two 5-byte jumps for the GP ICs to
hold — but **something must still initialize SP**, which today occupies
IC 0 as a 10-byte `load_imm_64` (and cannot fit in or between the slots).
Two options:

- **(a) Per-entry shims (jar-local SP stays in-blob):**

  ```text
  IC 0:   jump shim_refine        ; 5 bytes, own basic block
  IC 5:   jump shim_accumulate    ; 5 bytes, own basic block
  shim_refine:      load_imm_64 SP, stack_top ; jump e_entry
  shim_accumulate:  load_imm_64 SP, stack_top ; jump accumulate_vaddr
          …transpiled program…
  ```

  Keeps ICs 0/5 exact and needs no javm change, but the blob remains
  jar-hosted-only: a conformant JAM host initializes SP itself and a
  jar blob's shims would double-set it (harmless) while a *foreign* blob
  on jar would fault (no shim).

- **(b) Host-owned SP (GP-conformant) — DECIDED 2026-07-08:** javm kernel
  init sets `φ[1] = stack_top` (GP standard program initialization: the
  host owns SP), the transpiler drops the preamble entirely, and the
  prologue is just the two jumps. `stack_top` moves from an embedded
  instruction to blob container metadata (the SPI memory map). This is the
  only option that makes the blob itself GP-portable. Decision context:
  the jar fork's direction is **full JAM alignment** (see the fork's
  jam-alignment roadmap) — (a) is recorded only as the shape rejected.

Common to both:

- `ep_refine` = the existing ELF `e_entry` (`_start`) — refine behavior is
  preserved (via the shim in (a), via host SP init in (b)).
- `ep_accumulate` = the vaddr of an exported `accumulate` symbol, resolved
  from the ELF symtab and mapped through the linker's existing
  vaddr→PVM-PC fixup machinery.
- No `accumulate` symbol ⇒ IC 5 gets a **trap** — an accumulate invocation
  of a refine-only blob must fail loud, not fall through.
- Each prologue slot is a gas-block boundary.

### 3.2 Invocation + register ABI (javm + grey-state)

- `PvmInstance::initialize` gains an `entry_ic` parameter (0 = refine,
  5 = accumulate); `kernel_run` starts there.
- `grey-state::run_accumulate_pvm` drops the `φ[7]=1` hack and invokes at
  IC 5. Refine/is-authorized call sites pass 0 (is-authorized is
  prologue-compatible — authorizers are separate blobs whose `_start` is
  the check).
- **Register-ABI shift — DECIDED 2026-07-08 (with the fork's JAM-alignment
  direction):** args move to GP's convention (`ω_7` = args address,
  `ω_8` = length) **in the same migration** — every guest must be
  recompiled for the prologue anyway, so this is the one cheap moment;
  `φ[7]` is freed by dropping the selector.

### 3.3 Spec (jar Lean)

- Converge the `.v2` capability branch of `accone` to `entryPC = 5` (the
  gp072 branch already models it — the remaining work is the branch
  grey-state actually implements).
- Retire `Ψ_T`/`onTransfer` (dead code; GP main removed it; transfers stay
  `AccumulationInput.transfer`).
- Record the pinned GP commit hash in the spec header.

### 3.4 vos side

- **vos-macros** emit two exported entries: `_start` (refine — unchanged)
  and `accumulate` — the thin generated APPLY of
  `work-result-contract.md` §4 (FETCH operand items → verify anchor →
  apply effects via real hostcalls → reply). This is A15; it replaces the
  deleted `run_accumulate_service` with something *reachable and tested*.
- **vos runtime**: keeps invoking refine at IC 0. The A15 parity gate runs
  the guest accumulate in a PVM over recorded work-results and asserts
  byte-identical storage vs the native drain.
- **`.vos_meta`** records `entry_abi = 2` for prologue-carrying blobs; the
  host only attempts IC-5 invocation on blobs that declare it (old
  installed blobs keep working refine-only).
- **zk re-pin**: rebuilding any provable actor with the prologue-emitting
  transpiler changes its blob bytes and therefore its program commitment
  and canonical-shape ids — the federation `{C_0, C_1}` allowlist (and any
  other pinned commitment) must be re-derived **in the same change** as the
  rebuild, or chain verification silently fails (precedent: the short-tail
  re-pin).

## 4. Migration steps

| Repo | Step | Size |
|---|---|---|
| jar | javm: host-owned SP (`φ[1] = stack_top` at kernel init; stack_top via container metadata) + `entry_ic` parameter — or per-entry shims if (a) | S–M |
| jar | grey-transpiler: emit the two-slot prologue (+ drop the SP preamble under (b)); `accumulate` symtab resolution; trap slot when absent | M |
| jar | port `φ[7]`-dispatch guests (`pixels-service`) to exported `accumulate`; rebuild in-tree service blobs and grey-state test fixtures with the prologue transpiler | S–M |
| jar | grey-state: accumulate invokes IC 5, drop `φ[7]=1`; args-register shift if decided (§3.2) | S |
| jar | Lean spec: converge the `.v2` branch to IC 5; retire `Ψ_T`; pin the GP commit | S |
| vos | macro `accumulate` entry + guest APPLY + parity gate (= A15, after the work-result contract lands) | L |
| vos | `.vos_meta` `entry_abi` marker + host gating | S |
| vos | re-derive + re-pin zk program commitments for every provable actor rebuilt with the prologue transpiler (gate rebuild and re-pin together) | S |

Ordering: the jar javm/transpiler steps are independent of everything in
the vos workstreams and can start immediately; the guest ports + fixture
rebuilds sit between the transpiler step and the grey-state IC-5 switch;
vos A15 waits on all of jar's plus A7 (payload v3).

## 5. Open questions

- Whether grey's `machine` (nested-PVM) hostcall constrains inner-blob
  entry conventions for code-hash Tasks (A9) — inner Tasks are
  refine-shaped and enter at 0, so the prologue is compatible, but the
  Task ABI doc should say so explicitly once A9 lands.

(§3.1 (b) host-owned SP and the §3.2 register-ABI shift were both decided
2026-07-08 as part of the fork's JAM-alignment direction.)
