# zkPVM

> Scaffold — to be expanded.

The `pvm/proof/` crate produces succinct proofs of PVM execution using
[Stwo](https://github.com/starkware-libs/stwo). It lets a verifier check
that a PVM program ran correctly without re-executing it — useful for
trust-minimized off-critical-path computation, light-client
verification of actor state transitions, and anonymous credentials in
private collaborative applications.

## What this chapter will cover

- The chip set: CPU, memory, register-auth, branch, ALU, … and how
  they connect via the lookup framework
- How a PVM trace is lifted into Stwo columns
- Output binding: how the proof commits to the actor's outputs as
  well as its execution
- Precompiles (`pvm/proof/precompiles`) and the derive macro
  (`pvm/proof/derive`) that authors them
- The verifier (`pvm/proof/verifier`) — what a thin checker looks like
- Performance: where the cycles go and which chips dominate
- Fuzzing (`pvm/proof/fuzz`) — out-of-workspace because of nightly +
  `panic = abort`
- How VOS uses zkPVM for the [Private Economy](private-economy.md)
  (anonymous payments, voting, credentials)

## Source map

- [`pvm/proof/`](https://github.com/virto-network/vos/tree/master/pvm/proof)
- [`pvm/proof/derive/`](https://github.com/virto-network/vos/tree/master/pvm/proof/derive)
- [`pvm/proof/precompiles/`](https://github.com/virto-network/vos/tree/master/pvm/proof/precompiles)
- [`pvm/proof/verifier/`](https://github.com/virto-network/vos/tree/master/pvm/proof/verifier)
- [`pvm/proof/fuzz/`](https://github.com/virto-network/vos/tree/master/pvm/proof/fuzz)
