# Examples

The examples use the same signed package and root-service path as production.

| Example | Demonstrates |
| --- | --- |
| `counter` | minimal state and query handlers |
| `shared-board` | convergent shared state |
| `workflow` | durable actor calls and suspension |
| `private-age` + `age-gate` | private input and attested claims |

Build all examples:

```bash
just build-examples
```

Package one example:

```bash
cargo run -p vosx -- build examples/actors/counter --name counter
```
