# Reading map for an audit

Where the code is that decides what a verifier accepts, path by path, in
the crates under `pvm/proof`. [SECURITY.md](SECURITY.md) says what a
verified proof proves and what the audit covers; this page says which
files and functions to read for it. Paths below are relative to
`pvm/proof/`; `src/` is `vos-pvm-proof`'s.

## The rule in `vos-pvm-proof`

**An item not behind the `prover` feature is verifier-side:** compiled
into the verifier build, though not every such item is read on a
verifier's path (a few constants of a chip's layout are the prover's
alone). The crate's `--no-default-features` build, which also leaves out
the `wire` feature's checks, compiles exactly those items, and
`just check-no-std` builds it for `thumbv7em-none-eabihf` and
`wasm32-unknown-unknown` through `vos-pvm-proof-verifier`, so check code
that called into prover code would fail to compile there.

Prover code sits in child modules, each declared on one line at the edge
of its parent, `#[cfg(feature = "prover")] mod fill;`, with a gated
`pub use` when the parent re-exports one of its items under the parent's
path. A child sees its parent's private items, so no public path or
visibility outside the parent depends on where an item sits:

| parent | its prover half |
|---|---|
| a chip, `src/chips/<chip>.rs` or `<chip>/mod.rs`: columns, `BuiltInComponent::add_constraints` | `src/chips/<chip>/fill.rs`: `impl BuiltInProverComponent`, the helpers and constants only it reads |
| `src/chips/blake2b/address.rs` | `address/trace.rs` |
| `src/chips/cpu/cut.rs`: `CpuColumns`, `ProgramCpuChip`'s AIR | `cut/families.rs` (the columns a code keeps), `cut/fill.rs` (the cut trace) |
| `src/device.rs`: the device chip set, its order | `device/code.rs` (`device_chips_of_code`), `device/run.rs` (`DeviceLayout`, `DeviceRun`) |
| `src/page_merkle.rs`: the page-hash constants and chaining | `page_merkle/host.rs`: the host's tree, roots and multiproofs |
| `src/core/step.rs`, `src/memory_layout.rs`, `src/sparse_memory.rs` | `step/trace.rs`, `memory_layout/host.rs`, `sparse_memory/host.rs` |
| `src/framework/traits/{builtin,erased}.rs`: the verifier's chip traits | `builtin/prover.rs`, `erased/prover.rs`: `BuiltInProverComponent`, `MachineProverComponent` |
| `src/poseidon2/mod.rs`: the hasher and the channel | `poseidon2/simd_backend.rs`: the prover's backends |
| `src/masked/mod.rs`: the masked device set | `masked/trace.rs` |
| `src/lib.rs`: the chip table (`chips!`) | `src/prove/active.rs`: which chips a trace activates |

Whole modules behind `prover`: `side_note`, `kernel`, `prove`, `verify`
(which takes a `SideNote`; the side-note-free verifier is
`vos-pvm-proof-verifier`), `segment`'s bounds, cursor and windows, the tracer
(`core/tracing.rs`), the trace builders and the CPU's `classify`,
`reg_access`, `trace_fill/` and `interaction/`. Two type aliases have a
twin per configuration, side by side in `src/lib.rs`: `DynChip`, the chip
tables' trait object, and `DynComponent`, Stwo's component the masked set
holds; each is the verifier's trait without `prover` and the prover's
subtrait with it, which verification upcasts. The tables themselves are
written once.

**The `prover` feature is not the trust boundary.** No production binary
builds the verifier-only configuration: `vos-node` and `vos-light` link
`vos-pvm-proof` with `prover` through `vos-pvm-recair`. That build serves
the reference verifier and the compile check above. The code that fixes
what a verifier holds a proof to (the pin code below) is behind `prover`,
and two of the four production verifiers are not in `src/` at all.

## Three kinds of code

| kind | does | trusted for | in `vos-pvm-proof` |
|---|---|---|---|
| **check** | runs on every proof: constraints, transcript, PCS | soundness | ungated |
| **pin** | runs once a program: computes what the verifier holds a proof to | soundness | behind `prover`, but for the program id's derivation |
| **fill** | runs once a proof: tracer, trace fill, interaction trace, masks | completeness and zero-knowledge, not soundness | behind `prover` |

Pin code stays behind `prover`, among the fill code it shares a trait
with, but for one file: `src/program_id.rs` is ungated, shared by check and
pin (`KernelEntry::of` derives a kernel's entry state from its blob,
`KernelProgram::id` its id, both run by `verify_kernel_chain` and the
leaf). Read it as trusted:

- `src/chips/cpu/cut/families.rs`: `FAMILIES`, `CpuColumns::always`,
  `CpuColumns::of_code`: which CPU columns a device program keeps, hence
  which of the CPU's constraints its verifier drops.
- `src/device/code.rs`: `device_chips_of_code`, a device program's chip set,
  with `src/prove/active.rs`: `opcode_component_mask`, the chips an opcode
  activates.
- `src/prove/preprocessed.rs`: `preprocessed_root`, the root of a chip
  set's preprocessed columns, through the blanket
  `MachineProverComponent::generate_preprocessed_trace`
  (`src/framework/traits/erased/prover.rs`).
- `BuiltInProverComponent::generate_preprocessed_trace`, a method of the
  fill trait, in each chip's `fill.rs`; every one feeds the preprocessed
  root a verifier holds. Six read the program:
  `src/chips/program_memory/fill.rs` (the code table every step is bound
  to), `jump_table/fill.rs`, `memory_page/fill.rs` (the regions and their
  permissions), `device_boundary/fill.rs` (`DeviceBoundaryChip`'s entry),
  `word_memory/data/fill.rs` (the program's data) and
  `word_memory/boundary/fill.rs`. The others are fixed tables:
  `bitwise_lookup`, `bitwise_and_byte`, `byte_to_bits`, `popcount`,
  `bitcount`, `power_of_two`, `range_multiplicity`, `blake2b`,
  `blake2b/boundary`, `word_memory` and `device_boundary` (`DeviceIoChip`).
- `src/masked/trace.rs`: `device_preprocessed`; `src/kernel.rs`:
  `kernel_side_note`; `src/prove/shaped.rs`: `program_commitment_for_shape`;
  `recair/src/leaf/program.rs`: `kernel_program`, a kernel's program from
  its install record.
- `recair/src/device.rs`: `Program::of`, `Program::released`, `program_id`
  and `Program::verifier`. A node gets a device program's `Verifier` by
  building its prover: `DeviceProver::install` commits the preprocessed
  tree (`recair/src/masked/device.rs`), and `.verifier()` keeps the
  program, its masked format and its id (`node/host/src/node/admin.rs`:
  `device_program`; `node/host/src/credentialed.rs`). Ingress needs the
  prover's backend at install, whatever the layout.

## The four production paths

| path | who checks it | entry | code that decides what is checked | what pins it |
|---|---|---|---|---|
| **39**, the masked wrap | a venue: natively, in wasm32, or as a PVM guest | `statement/src/lib.rs`: `admit`, then `Admitted::verify` → `final-verifier/src/lib.rs`: `verify` (`decode`, `Decoded::verify`) → `final-verifier/src/masked.rs`: `verify` → `verify_with` → `verify_masked` | `statement/src/lib.rs`; `final-verifier/src/{lib,masked,layout,constants}.rs`; `recair-air/src/` (`gate.rs`, `transcript.rs`, `p2.rs`, `h8.rs`, `qm31.rs`, `masked/`); `vos-pvm-poseidon2` without `packed`; `anchor/src/venue.rs`; Stwo's verifier core | `PREPROCESSED_ROOT_39` (`final-verifier/src/constants.rs`, the wrap circuit), `MASKED_WRAP` (`final-verifier/src/masked.rs`, the masked format `verify_with` holds a proof to) and the statement's program id |
| **32**, leaves and folds | the fold and wrap circuits, in-AIR; natively only `recair/src/prove.rs`: `verify`, in tests and the prover's own check | none outside the circuits | `recair-air/src/` without `masked/`; the circuit builders in `recair/src/`: `fold/`, `wrap.rs`, `verifier/`, `context/`, `circuit.rs`, `gadgets.rs`, `value.rs` | `H_FOLD` (`src/constants.rs`), a constant of the wrap circuit |
| **41**, a node's segment | a leaf circuit, in-AIR; no native verifier runs in production | `verifier/src/lib.rs`: `verify_standalone`, `verify_kernel_segment`, `verify_kernel_chain`, the reference a leaf is tested against | the node chip set and the AIR plumbing (below); `src/{proof,format,pcs,security,shape,program_id,boundary_binding}.rs`; `recair/src/compile/` (constraints to gates), `recair/src/leaf/`, `recair/src/verifier/{segment,shape,logup}.rs` | the program id: `src/program_id.rs` (`KernelProgram`, `LeafCircuits`, `ProgramId`), each class's shape, preprocessed root and entry state |
| **47**, a device proof | a node's ingress, natively | `recair/src/device.rs`: `Verifier::verify` → `recair/src/masked/device.rs`: `verify_device_in` → `final-verifier/src/masked.rs`: `verify_masked` | `final-verifier/src/masked.rs`; `recair-air/src/masked/`; `src/masked/mod.rs`; `src/device.rs`; the device chip set and the plumbing (below); `src/format.rs`; the verify half of `recair/src/device.rs` and `recair/src/masked/{device,mod}.rs`, which mix proving and verifying under no feature | `recair/src/device.rs`: `program_id` (the format, the chips, the CPU cut, the log sizes, the preprocessed root) |

The masking's zero-knowledge rests on prover code: `recair/src/masked/`
and `src/masked/trace.rs`.

### The chip sets

Each chip's check code is its parent file (or directory, its prover
modules aside); `src/lib.rs` holds both tables, the node's (`chips!`) and
the device's own chips over it (`device_chips!`), and `src/device.rs`
(`DEVICE_ORDER`, `device_chip`) the device set's order and indices.

| chips | node segment (41) | device (47) |
|---|---|---|
| `src/chips/cpu/` (`columns.rs`, `constraints/`, `tuples.rs`), `blake2b/` (`mod.rs`, `address.rs`, `call.rs`, `columns.rs`, `compression/{mod,constraints}.rs`, `consts.rs`, `sw.rs`), `poseidon2.rs`, `register_memory.rs`, `program_memory.rs`, `jump_table.rs`, `witness_input.rs`, `range_multiplicity.rs`, `bitwise_lookup.rs`, `power_of_two.rs`, `popcount.rs`, `bitcount.rs`, `byte_to_bits.rs`, `mul.rs`, `bitwise.rs`, `compare.rs`, `divrem/{mod,constraints}.rs`, `bitwise_and_byte.rs` | yes | yes |
| `memory.rs` (the byte ledger), `blake2b/boundary.rs`, `memory_page.rs`, `memory_merkle.rs`, `memory_root_boundary.rs` (the page tree), `register_memory_boundary.rs`, `register_memory_closing.rs`, `program_boundary.rs` | yes | no |
| `cpu/cut.rs` (`ProgramCpuChip`, the CPU with its cut columns zero), `word_memory/mod.rs` (`WordMemoryChip`, in the byte ledger's place), `word_memory/boundary.rs`, `word_memory/data.rs`, `device_boundary.rs` (`DeviceBoundaryChip`, `DeviceIoChip`) | no | yes |

The AIR plumbing both sets share: `src/framework/` (`eval.rs`,
`traits/builtin.rs`, `traits/erased.rs`), `src/lookups/` (the relations),
`src/trace/eval.rs`, `src/air_column/`, `src/framework_access.rs` and
`src/chips/ordering.rs` (the ledgers' ordering delta).
