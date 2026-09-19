# Examples

These examples use the public Agent SDK and the standard runtime embedded in
`vosx`. Actor builds produce the single signed `VOS3` package format; none of
the examples depends on a node-specific execution or signing hostcall.

| Example | Profile / lane | Demonstrates |
| --- | --- | --- |
| `counter` | Local or Shared / Linear | minimal durable state and queries |
| `shared-board` | Shared / Linear + Merge | one hybrid collaborative actor |
| `private-notes` | Private / Merge | personal multi-node convergent notes |
| `local-signer` | Local / Local + const | explicit two-step signing workflow |
| `custom-linear` | Local or Shared / Linear | deterministic scheduled runtime |

Build all examples:

```bash
just build-examples
```

The example workspaces pin `nightly-2026-03-20` with `rust-src`; the recipe
honors those toolchain files and uses locked dependencies. Set `TMPDIR` to a
disk-backed directory if your system mounts `/tmp` in RAM. Building these
examples does not replace the independent production-artifact reproduction gate.

Package one example:

```bash
cargo run -p vosx -- actor build examples/actors/counter --name counter
```

The scheduled runtime lives in `examples/agent-runtimes/custom-linear`; it
implements the mandatory management ABI and declares scheduling explicitly.
`actor` is the portable authoring namespace. The Linux Local lifecycle uses
`space create-local-agent` and `space install-local-actor`; there is no current
top-level `agent` command. See [Getting started](../docs/getting-started.md).
The profile/lane table describes SDK examples, not production deployment
qualification for every profile; ordinary Shared genesis and Private/Attested
proof qualification remain release gates.
