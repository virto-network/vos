# Examples

The examples cover both the standard agent runtime and the established service
runtime. Agent actors build as signed `VOSK` packages; service actors build as
signed `VOSP` packages accepted by the current `space publish` path.

| Example | Runtime | Demonstrates |
| --- | --- | --- |
| `counter` | standard agent | minimal state and query handlers |
| `shared-board` | standard agent | linear and convergent state in one actor |
| `workflow` | service | durable actor calls and suspension |
| `private-age` | service | private input and attested claims |
| `age-gate` | native verifier | verification of the attested age claim |

Build all examples:

```bash
just build-examples
```

Package one example:

```bash
cargo run -p vosx -- agent build examples/actors/counter --name counter
```

Package a service actor:

```bash
cargo run -p vosx -- build examples/actors/workflow --name workflow
```
