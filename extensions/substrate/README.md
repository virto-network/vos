# Substrate extension

A native VOS actor backed by Sube and smoldot. Its default connection is a
light client for Kreivo (parachain 2281) on Kusama; no public JSON-RPC service
is required.

The actor-facing API is generated as `SubstrateExtensionRef`:

- `status()` lazily connects and returns genesis/finalized chain identity.
- `query(path, at)` reads one constant or fully-keyed storage value.
- `query_map(path, limit, cursor)` reads a snapshot-pinned page; an empty
  cursor starts at the current finalized block. Pages can be shorter than the
  requested limit while still returning a continuation cursor because the
  light client caps trie-proof work per request.
- `prepare_transaction(request)` freezes a metadata-driven V4 signing
  payload. Signing and nonce accounts are separate fields.
- `submit_transaction(id, signature, wait_for)` consumes the request and waits
  synchronously for best-chain inclusion or finalization. The receipt always
  identifies the submitted extrinsic by hash; its full hex and tail events are
  omitted when necessary to stay inside the reply bound.
- `cancel_transaction(id)` releases an unused signing request.

No signing keys are accepted or retained. V5/general extrinsics are not
exposed. The light client and pending request table are transient actor fields,
so snapshots persist only operator configuration and the request-id counter.
Dropping or reloading the actor drops Sube and joins its smoldot executor before
the extension library can unload.

The first query may spend up to 120 seconds initializing and synchronizing the
light client. Subsequent queries normally use the already-running client.
Map cursors retain at most 16 finalized snapshots, expire after four minutes,
and are limited to 32 pages. Returned values are proof-checked at that retained
hash; key discovery walks small lexicographic trie partitions so it never asks
a peer for one unbounded whole-map proof.

Build the `.so` with:

```sh
cargo build -p substrate-extension --release
```

For Ref-only actor dependencies:

```toml
substrate-extension = { path = "../../extensions/substrate", default-features = false }
```

Chain-spec sources, patches, and checksums are recorded in
[`assets/README.md`](assets/README.md).
