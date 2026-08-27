# Native extensions

Native extensions are request/response actors compiled as shared libraries.
They use `#[actor]` and `#[messages]`, receive typed VOS messages, and may ask
actors or perform host work before returning a result. The proof producer is
the main example.

Extensions are trusted process code. Loading one grants it the daemon's OS
authority; VOS does not pretend to sandbox native code. `intra_caps` only
limits which actor identities and roles an extension may relay through VOS.

Extensions do not own listeners or long-lived connections. Protocol ingress
belongs to the node, where connection limits, authentication, shutdown, and
identity preservation can be enforced consistently. See [HTTP
ingress](http-ingress.md) and [SSH space shell](ssh-ingress.md).

Use an extension when the interaction has this shape:

```mermaid
sequenceDiagram
    participant Actor
    participant Extension
    participant Host
    Actor->>Extension: typed request
    Extension->>Host: bounded host operation
    Host-->>Extension: result
    Extension-->>Actor: typed response
```

Do not use an extension to implement an HTTP, SSH, database-proxy, or other
connection server. Add such a protocol as a built-in ingress adapter instead.
