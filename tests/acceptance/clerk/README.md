# Clerk acceptance application

Clerk is the complex end-to-end acceptance application for replicated private
payments. It is deliberately kept outside the beginner examples.

- `space-clerk-demo.toml` runs the single-node gateway scenario.
- `space-bank-a.toml` and `space-bank-b.toml` define separate Raft-backed bank
  roots and durable cross-bank bridges.
- `space-venue.toml` defines the neutral settlement venue.

The application actors live in `actors/clerk-{ledger,bridge,settle}`. Build the
protocol-pinned service PVM, then package the application through the v2 path:

```sh
just package-clerk dist/vos-service.pvm dist/clerk
```

The manifests install those exact signed `.vos` bytes from `dist/clerk`; a
registry must never retranspile the actors' ELF diagnostics. The bridge package
signs its `clerk-ledger` dependency, so voucher redemption crosses root trees
through the durable v2 outbox/inbox path rather than a route-only application
address. Manifest paths are relative to this directory and retain distinct bank
replication IDs.
