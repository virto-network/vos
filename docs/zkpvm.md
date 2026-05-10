# zkPVM

> Scaffold — to be expanded.

The `zkpvm/` crate produces succinct proofs of PVM execution using
[Stwo](https://github.com/starkware-libs/stwo). It lets a verifier check
that a PVM program ran correctly without re-executing it — useful for
trust-minimized off-critical-path computation, light-client
verification of actor state transitions, and anonymous credentials in
Kunekt-style applications.

## What this chapter will cover

- The chip set: CPU, memory, register-auth, branch, ALU, … and how
  they connect via the lookup framework
- How a PVM trace is lifted into Stwo columns
- Output binding: how the proof commits to the actor's outputs as
  well as its execution
- Precompiles (`zkpvm/precompiles`) and the derive macro
  (`zkpvm/derive`) that authors them
- The verifier (`zkpvm/verifier`) — what a thin checker looks like
- Performance: where the cycles go and which chips dominate
- Fuzzing (`zkpvm/fuzz`) — out-of-workspace because of nightly +
  `panic = abort`
- How VOS uses zkPVM for the [Private Economy](private-economy.md)
  (anonymous payments, voting, credentials)

## Source map

- [`zkpvm/`](https://github.com/virto-network/vos/tree/master/zkpvm)
- [`zkpvm/derive/`](https://github.com/virto-network/vos/tree/master/zkpvm/derive)
- [`zkpvm/precompiles/`](https://github.com/virto-network/vos/tree/master/zkpvm/precompiles)
- [`zkpvm/verifier/`](https://github.com/virto-network/vos/tree/master/zkpvm/verifier)
- [`zkpvm/fuzz/`](https://github.com/virto-network/vos/tree/master/zkpvm/fuzz)
