# PVM Runtime

> Scaffold — to be expanded.

## What this chapter will cover

- The JAM-aligned PVM (RISC-V) target and why VOS picked it
- Determinism guarantees: refine vs accumulate, journaling, continuations
- Hostcalls and the ABI surface (`vos::abi`)
- Worker plugins (native) vs actors (PVM) vs WASM guests
- The scheduler: lifecycle states, yielding, message delivery
- How `vos-macros` lowers `#[actor] / #[messages] / #[msg]` into
  the PVM `_start` and `accumulate` entry points
- Built-in PVM actors bundled with `vosx` (e.g. `space-registry`)

## Source map

- [`vos/src/runtime.rs`](https://github.com/virto-network/vos/tree/master/vos/src/runtime.rs)
- [`vos/src/actors/`](https://github.com/virto-network/vos/tree/master/vos/src/actors)
- [`vos/src/abi/`](https://github.com/virto-network/vos/tree/master/vos/src/abi)
- [`vos-macros/src/lib.rs`](https://github.com/virto-network/vos/tree/master/vos-macros/src/lib.rs)
