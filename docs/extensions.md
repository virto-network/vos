# Native extensions

Native extensions are request/response actors compiled as shared libraries.
They use `#[actor]` and `#[messages]`, receive typed VOS messages, and may ask
actors or perform host work before returning a result. The proof producer is
the main example.

Extensions are trusted process code. Loading one grants it the daemon's OS
authority; VOS does not pretend to sandbox native code. `intra_caps` only
limits which actor identities and roles an extension may relay through VOS.

Extensions do not own listeners. Protocol ingress belongs to the node, where
connection limits, authentication, shutdown, and identity preservation can be
enforced consistently. See [HTTP ingress](http-ingress.md) and [SSH space
shell](ssh-ingress.md).

An extension may own an outbound client session when that session is the
bounded host capability it exposes. It must accept no inbound connections,
keep its work and replies bounded, and synchronously stop/join every background
task from its destructor before the shared library can be unloaded. The
Substrate extension is the reference case: smoldot owns the Substrate protocol
stack above outbound TCP sockets, while a joinable executor is tied to the
extension actor's lifetime. VOS's libp2p swarm is not reused because its peer
identity, protocols, connection ownership, and async runtime belong to the VOS
space rather than to a Substrate light client.

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

## Substrate light client

`extensions/substrate` provides a Kreivo-on-Kusama light client with pinned,
compressed chain specifications. Actors can use its generated
`SubstrateExtensionRef` without linking the native backend. The public surface
supports finalized single-value queries, snapshot-pinned map pagination, and
two-stage externally-signed V4 transactions. It never accepts a seed, secret
key, RPC URL, or bootnode from an actor request.

Operators may replace the complete parachain and relay specifications through
host-local init configuration:

```toml
[[extension]]
name = "substrate"
path = "target/release/libsubstrate_extension.so"

[extension.init]
network = "kreivo-kusama"
chain_spec_path = "/etc/vos/kreivo.json.zst"
relay_spec_path = "/etc/vos/kusama.json.zst"
```

Omit both paths for the bundled defaults. Actor-visible requests are capped at
32 map rows, a 7 KiB encoded success reply, 16 active map snapshots, 32 pages
per map cursor, and 32 pending signing payloads. Map pages may be short while a
non-empty cursor indicates more bounded trie partitions. Map cursors and
unsigned preparations expire after four minutes; only one automatic-nonce
request per nonce account may be pending at once.
