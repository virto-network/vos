# Examples

The examples cover both portable AgentActors hosted by the standard Agent and
the established service runtime. `vosx actor build` packages a portable
AgentActor as signed `VOS3`; the legacy service examples remain runtime and
integration fixtures during the production cutover.

| Example | Runtime | Demonstrates |
| --- | --- | --- |
| `counter` | Agent-hosted | minimal state and query handlers |
| `shared-board` | Agent-hosted | linear and convergent state in one actor |
| `workflow` | service | durable actor calls and suspension |
| `private-age` | service | private input and attested claims |
| `age-gate` | native verifier | verification of the attested age claim |

Build all examples:

```bash
just build-examples
```

Package one example:

```bash
cargo run -p vosx -- actor build examples/actors/counter --name counter
```

`actor` is the portable authoring namespace. `agent` remains reserved for
operations and does not expose `new` or `build` authoring aliases.
