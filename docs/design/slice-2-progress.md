# Slice 2 progress

Results for each step of `slice-2-one-node.md`.

## Step 2.1: wire types and host-call surface

**Done:**

- **`vos-wire`** (`agent/wire`, `no_std`), SCALE-coded with `pvm/codec`:
  - ids, the batch and its inputs (requests, messages, admin commands);
  - the work result: the version read, the batch time and seed, and its
    steps. A step either ran (the input it answers, `Done` or `Failed`, the
    gas per instance, writes, outgoing messages and attests) or was
    refused (an input out of order or in an expired session), which
    consumes nothing and cannot carry effects;
  - principals: clients, agents, and the calling instance of a nested
    call, so a callee never acts with its caller's caller's roles;
  - the actor ABI (`abi`): operation ids `0x500..`, the register
    convention of each, the table of operations per invocation kind,
    prices, per-step caps, result, failure and refusal codes. A nested
    call returns the callee's own error, with its writes discarded, or a
    role refusal; any other callee failure fails the step;
  - the agent's key layout (`keys`): system keys under `0x00`, instance
    state under `0x01 ∥ be32(instance)`;
  - the Gray Paper structures (`jam`): refine's arguments and accumulate's
    inputs (operands and deferred transfers);
  - the owner's defaults (W = 64, one-hour expiry, 10M handler gas, 1G
    refine gas).
- **Refine host** (`vos_pvm::refine_host`): `state_read` (`0x481`) serves
  the node's applied state through a `StateReader` and costs 1 gas per
  byte copied; `gas` (0) and `log` (100) are served; `try_run_jam` runs as a
  JAM node would, answering `WHAT` to every call it does not serve,
  `instantiate` and `state_read` included. The refine allow-list is the
  served set.
- **Accumulate host** (`vos_pvm::accumulate_host`): the accumulate entry
  (instruction counter 5) with `E(t, s, |inputs|)`, serving `fetch` (kinds
  14 and 15), `read`, `write`, `gas` and `log`; everything else answers
  `WHAT`. `read` of another service answers `NONE`.
- The Gray Paper ids (0, 2–8, 100) and the VOS extensions (`0x480`,
  `0x481`) are pinned by test.

**Captured from PolkaJam.** The SJ echo service, rerun on the PolkaJam
0.1.29 testnet (Gray Paper 0.8.0), stored three accumulate inputs: its
endowment transfer, an operand for an item that refined to
`vos:hello-jam`, and an operand for an item refined with 50 gas. They are
fixture tests in `agent/wire/tests/wire.rs`. They show that:

- an accumulate input starts with its kind: 0 for an operand, 1 for a
  deferred transfer;
- an operand is `p ∥ e ∥ a ∥ y ∥ g ∥ O(result) ∥ ↕trace`, with the gas
  limit as a natural, as the Gray Paper text has it;
- out of gas is error tag 1, with nothing after it;
- a transfer is `E4(source) ∥ E4(destination) ∥ E8(amount) ∥ memo[128] ∥
  E8(gas)`.

The PolkaJam in `~/bin/polkajam` is 0.1.27 (Gray Paper 0.7.2); captures
need the 0.1.29 nightly.

**Toolchain.** fjall 3.1 (step 2.2) needs rustc 1.90. The workspace moved
from `nightly-2025-05-09` to `nightly-2025-07-14` (1.90.0-nightly), the
newest nightly on which the pinned stwo still builds: later nightlies
dropped `array_chunks_mut`. The guests keep their own toolchain; the root
toolchain gains `rust-src` for the settlement verifier's standard-library
build. fjall is pinned exactly, since a 1.90 pre-release satisfies its
`rust-version` only by Cargo ignoring the suffix. The newer clippy's lints
(`manual_is_multiple_of`, `cloned_ref_to_slice_refs` and a few
machine-fixable ones) are fixed across the workspace.

**Compiler bugs the new toolchain exposed.** Built with the new rustc, the
settlement verifier panicked on the PVM after 4.6M instructions, while the
same ELF accepts under `qemu-riscv64`. Comparing the two runs' pc traces,
mapped through the linker's address map, found the first divergence at a
`beq zero, zero` that LLVM 21 emits. A differential property test
(`pvm/compiler/src/linker_differential.rs`) then compared random RV64IM
programs, with x0 weighted in, against a reference interpreter through
the production link path, and found the rest:

- a branch between two x0 operands, and OP and OP-32 forms with x0
  sources, read PVM register 0, which holds the return address, not zero;
  division and remainder by x0 were also folded wrongly;
- a `lui` before a direct branch target was emitted at the target, so
  every branch to it ran the `lui`: direct branch and jump targets now
  stop fusion as symbols do;
- peephole passes removed an instruction by clearing its bitmask, which
  folds its bytes into the previous instruction and changes that
  instruction's immediate length. The dead-`load_imm` pass is removed and
  the memory fusion now writes the fused instruction in the `load_imm`'s
  place.

The settlement verifier accepts again, in 10,683,638 instructions (qemu:
10,675,993 RISC-V instructions).

The pin is held between two constraints that will diverge: fjall wants a
newer rustc, the pinned stwo an older one. Moving stwo, which the privacy
work needs anyway for zero-knowledge masking, unblocks the toolchain.
