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

Package one example:

```bash
cargo run -p vosx -- actor build examples/actors/counter --name counter
```

The scheduled runtime lives in `examples/agent-runtimes/custom-linear`; it
implements the mandatory management ABI and declares scheduling explicitly.
`actor` is the portable authoring namespace, while `agent` is reserved for
operations on durable Agent instances.
