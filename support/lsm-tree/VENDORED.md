# lsm-tree 3.1.10, patched

The published source of [lsm-tree](https://github.com/fjall-rs/lsm-tree)
3.1.10 (MIT or Apache-2.0), as crates.io ships it, with one change and
one fix to its tests. The
workspace takes it in place of the published crate through
`[patch.crates-io]`, so fjall builds on it.

**The change** (`src/version/super_version.rs`, the only source that
differs): a version `SuperVersions::maintenance` pops has its memtables
freed on a thread of its own (`lsm-release`, started on first use), not
where it is popped. Its tables are dropped there, as before.

**Why:** `maintenance` runs under the version history's write lock: in
lsm-tree after a flush or a compaction, and in fjall after every memtable
rotation, on every keyspace. A popped version can hold the last reference
to a flushed memtable, and freeing it (a skiplist of every item the
memtable held: over 100 ms for 64 MiB) held every reader and writer of the
tree for as long. Under load that was a stall of 100–300 ms a few times a
minute, on every agent of a node.

**Why only memtables:** a deleted table removes its file when dropped.
Removed later, on that thread, the file could already be a reopened
tree's, with the same table id.

**The tests' fix** (`src/time.rs`, compiled only for its tests): the clock
a test sets is per thread, not the process's. Tests run on parallel
threads, and `fifo_ttl`'s clock (1,011 s) met
`fifo_ttl_then_limit_additional_drops_blob_unit`'s (10,000,000 s): both
of its tables expired, and it failed now and then in `just test`.

**What is ours:** that change and that fix; `tests/released_versions.rs`; `Cargo.toml`
without the benchmarks the published crate leaves out, and with an empty
`[workspace]`, so the crate is its own workspace; `Cargo.lock` for its
tests; and `UPSTREAM.md`, the change written up for upstream.

**How it builds:** as published, with its own warnings (shown, not
denied: `-D warnings` applies to the workspace's members). Its tests run
in `just test`: `cargo test --manifest-path support/lsm-tree/Cargo.toml`.

**Removed** once a release of lsm-tree (with fjall) frees popped
memtables outside the version lock: then the patch entry goes, and this
directory with it.
