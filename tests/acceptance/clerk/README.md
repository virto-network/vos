# Clerk acceptance application

Clerk is the complex end-to-end acceptance application for replicated private
payments. It is deliberately kept outside the beginner examples.

- `space-clerk-demo.toml` runs the single-node gateway scenario.
- `space-bank-a.toml` and `space-bank-b.toml` define separate Raft-backed bank
  roots and durable cross-bank bridges.
- `space-venue.toml` defines the neutral settlement venue.

The application actors live in `actors/clerk-{ledger,bridge,settle}`. Manifest
paths are relative to this directory and retain distinct bank replication IDs.
