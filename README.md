# VOS

VOS runs spaces: groups of nodes that host agents, programs compiled to
the PVM (the JAM Gray Paper's RISC-V virtual machine), each agent
replicated over its own Raft log. An agent's state is a committed map, its
calls run exactly once, and what it attests at a window's cut is proved
with a STARK and anchored at a venue (the JAM statements service, or
Kreivo's spaces pallet). Members act through credentials: a phone proves
it holds a member's secret, and the space learns a scoped, anonymous
origin rather than who the member is.

## Design

- [`docs/design/core-model.md`](docs/design/core-model.md): agents,
  actors, execution, state, replication, the JAM integration, the
  performance budgets and the scale test.
- [`docs/design/proving.md`](docs/design/proving.md): the proof layers,
  formats, masking, verifiers, roots and anchors, and the mobile device
  profile. [`docs/design/recursion-air.md`](docs/design/recursion-air.md)
  is the recursion AIR.
- [`docs/design/identity-and-authority.md`](docs/design/identity-and-authority.md):
  origins, guards, credentials and the threat model.
- [`docs/design/node-api.md`](docs/design/node-api.md): the node's binary
  API, its gateways and operator requests.
- [`docs/design/spaces-pallet.md`](docs/design/spaces-pallet.md): the
  design of Kreivo's spaces pallet, the venue VOS anchors at on Kreivo.
- [`docs/design/clerk-across-spaces.md`](docs/design/clerk-across-spaces.md):
  the Clerk's settlement across spaces, proposed.
- [`docs/design/open.md`](docs/design/open.md): known gaps and next work.
- [`docs/operations.md`](docs/operations.md): operating a space's nodes.
- The security notes: [`node/SECURITY.md`](node/SECURITY.md) (the
  credential surface), [`pvm/proof/SECURITY.md`](pvm/proof/SECURITY.md)
  (what a verified proof proves) and
  [`node/light/SECURITY.md`](node/light/SECURITY.md) (the light node and its device library).

## The crates

- `pvm/`: the PVM.
  - `runtime` (interpreter and recompiler), `compiler` (RISC-V ELF to
    PVM), `program` (the standard-program format), `codec`.
  - `proof/`: the STARK prover and verifiers: the zkVM, the recursion AIR
    (`recair`, `recair-air`), Poseidon2, the final verifier, the statement
    a venue judges, `anchor` (a space's identity, windows and roots), the
    JAM statements service and the precompile shims.
  - `guest/`: the guest toolchain; `bench`: benches and cross-host checks.
- `agent/`: the agent side.
  - `wire` (shared wire types), `sdk` and `sdk-macros` (`#[actor]`,
    `#[messages]`), `tree` (the committed maps' Merkle tree), `testkit`
    (a native host and the reference model of the default agent).
  - The guest programs: `default` (the default agent), `representative`,
    `credentials`, `test-actors`.
- `node/`: the node, and the light node.
  - `host` (storage, the leader loops, the API), `exec` (the agent
    program's runs, which the node and the light node share), `light` (the
    light node: local actors over its own store, and the device library,
    a member's credential proofs), `api` (the binary API),
    `net` (node-to-node channels), `prover` (the leader's prover worker),
    `venue` (anchoring and submitting statements), `jam` (an agent as a
    JAM service), `cli` (the `vos` command).
  - `http` and `gateway`: the HTTP front and the gateway, which hold no
    authority.
  - `checker`: the exactly-once checker and the shared test harness.
- `support/`: `vos-raft` (a `no_std` Raft core with a deterministic
  simulator) and `merkle-crdt`.
- `tools/`: development tooling no node links: `jam-dev` (a PolkaJam
  testnet's driver), `scale` (the scale test's harness) and `phone` (the
  phone bench).

## Build and test

The recipes are in the [`justfile`](justfile) (it runs under `nu`);
`just` lists them.

- `just check`: the quick gate after each change: formatting, the docs'
  links, the `no_std` builds, the leak checks, the lints and the fast
  suites of the node, the agent and the crates under them.
- `just ci`: everything but the prover suites, before a merge.
- `just test-proof`: the prover suites (run under a 12 GiB memory limit).
- `just ci-full`: `ci`, the prover suites, the soundness gates at their
  medium sizes and the fuzz targets a minute each.
- `just slice-gate`: the full gate: the leakage tests at their full sizes
  and the fuzz targets five minutes each.
- `just check-blobs`: the venue guests and agent programs rebuild to the
  hashes pinned in `blobs.lock`.
- `just e2e-chain`: an agent's statements proved and judged at a JAM
  statements service on a PolkaJam testnet.
