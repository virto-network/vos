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
  payload. Signing and nonce accounts are separate fields. Automatic nonce
  lookup requires a mortal transaction; explicitly managed nonces may still
  use an immortal era.
- `submit_transaction(id, signature, wait_for)` validates the signature,
  consumes the request immediately before network submission, and waits
  synchronously for best-chain inclusion or finalization. Automatic nonces
  require finalization; callers selecting best-block inclusion provide an
  explicit nonce. If submission has an ambiguous timeout or connection result,
  that automatic nonce remains reserved: another automatic request returns
  `NonceUncertain` until the finalized account nonce advances or the mortal era
  expires, while an explicitly managed nonce remains available as the recovery
  path. The receipt always identifies the submitted extrinsic by hash; its full
  hex and tail events are omitted when necessary to stay inside the reply bound.
- `cancel_transaction(id)` releases an unused signing request while that
  request is still live in the current extension process.

Transaction methods accept trusted local system/actor calls. Network peers and
credential-backed ingress callers require at least a `Member` space grant;
Noise transport identity by itself is not authorization. Signing request IDs
and map cursors are non-sequential capabilities bound to the caller identity
when VOS has one; anonymous read cursors remain bearer capabilities and share
the anonymous caller quota.

No signing keys are accepted or retained. V5/general extrinsics are not
exposed. The light client and pending signing data are transient actor fields;
snapshots persist operator configuration, the request-id counter, and bounded
automatic-nonce reservations so submission uncertainty survives a light-client
reconnect or actor reload. A restored reservation is conservatively treated as
possibly submitted and cannot be cancelled without its transient pending
request; finalized nonce advancement or mortal-era expiry retires it. `vosx`
enables instance-scoped persistence for installed extensions and refuses to
start an extension if storage cannot be opened or its saved schema cannot be
decoded. The snapshot envelope binds state to the actor's direct-field
fingerprint and declared `state_version`; bump `state_version` whenever the
archived representation or meaning of `Config` or `NonceReservation` changes.
Dropping or reloading the actor drops Sube and joins its smoldot
executor before the extension library can unload. A failed operation cleanup
poisons and drops the current light-client session instead of reusing uncertain
server state.

The first query may spend up to 105 seconds initializing and synchronizing the
light client. Subsequent queries normally use the already-running client.
Map cursors retain at most 16 finalized snapshots per caller and expire after
four minutes of inactivity. Returned values are proof-checked at that retained
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
