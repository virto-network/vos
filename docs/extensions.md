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

With a Ref-only dependency on `substrate-extension`, an actor binds the
generated API to that installed name rather than to an `ActorId`:

```toml
[dependencies]
vos = { version = "0.1", default-features = false, features = ["macros", "service", "native-extension-client"] }
substrate-extension = { version = "0.1", default-features = false }
```

```rust,ignore
let mut substrate = ctx
    .extension::<substrate_extension::SubstrateExtensionRef>("substrate")
    .await?;
let result = substrate.query("system/number".into(), None).await?;
```

`native-extension-client` is deliberately opt-in so actors that never invoke
native extensions retain their existing PVM binary and identity. Extension API
crates expose their typed handle by declaring the interface with
`#[messages(extension)]`; ordinary `#[messages]` interfaces do not generate
native-extension bindings.

The dedicated host route is node-local, capped at eight calls per Refine and
64 KiB in either direction, and is rejected for proof-requested invocations.
It is available only to durable `Local` roots. Raft and CRDT roots need a
future consensus-committed extension outbox before they can safely coordinate
node-local side effects; ephemeral roots cannot durably bind the result. A
queued native call can time out only while it is still cancelable. Once the
serial extension worker claims it, the bridge waits for the actual committed
reply, preventing a reported timeout from being followed by late work.
`BlockRef`s returned by status or a query are backed by transient authenticated
finalized-block tokens. The same caller can reuse one without an archive node;
arbitrary, cross-caller, expired, reloaded, or reconnected references return
`Stale`.

Omit both paths for the bundled defaults. Actor-visible requests are capped at
32 map rows, a 7 KiB encoded success reply, 16 reusable query block references
per caller, 16 active map snapshots per caller, and 32 pending signing payloads
per caller. Query references, map cursors, and unsigned preparations expire
after four minutes. Map pages may be short while a non-empty cursor indicates
more bounded trie partitions. Only one automatic-nonce
request per nonce account may be pending at once, and automatic-nonce requests
must be mortal and wait for finalization. An ambiguous submission keeps its
nonce reserved until the finalized account nonce advances or its mortal era
expires; automatic preparation reports `NonceUncertain` in the meantime, and
callers may recover with an explicitly managed nonce. These bounded
reservations, frozen preparations, and bounded submission outcomes are part of
the actor snapshot. Reconnecting the light client or reloading the extension
therefore does not silently make an uncertain nonce reusable. Replaying the
same native invocation returns its original signing payload or submission
outcome. Recovery after an uncommitted broadcast retains the original call and
account nonce, preventing a second execution; a persisted unresolved attempt
also pins the exact signature and inclusion target.

`vosx space up` gives every installed extension an instance-scoped state
database. Persistence setup and commits are fail-closed: a stateful reply is
not exposed until its state commits, and an unreadable or schema-incompatible
snapshot prevents that extension worker from starting instead of silently
constructing default state. `#[actor]` fingerprints direct state fields in the
snapshot envelope. Extension authors must also set `state_version` and bump it
when a persisted nested type changes incompatibly, for example
`#[actor(state_version = 2)]`.

Transaction preparation, submission, and cancellation accept trusted local
system calls. The host binds any caller grant to its exact actor identity;
Noise transport identity alone does not authorize nonce reservations or
signing capabilities. The current `vosx` cutover can load and persist an
extension and exposes Linux Local actor installation and canonical managed
invocation. It has no dynamic text-command fallback. The Local Counter release
checks do not qualify an end-to-end extension transaction/signing workflow;
see [current status](agent-saga-status.md).
Signing request IDs and map snapshot IDs remain non-sequential and
caller-bound; unauthenticated map reads use bearer cursors and share one
anonymous caller quota.
