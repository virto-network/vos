# lsm-tree 3.1.10, patched

The published source of [lsm-tree](https://github.com/fjall-rs/lsm-tree)
3.1.10 (MIT or Apache-2.0), as crates.io ships it, with two changes and
one fix to its tests. The workspace takes it in place of the published
crate through `[patch.crates-io]`, so fjall builds on it.

**The changes** (`src/version/super_version.rs`, the only source that
differs), each written up in [UPSTREAM.md](UPSTREAM.md):

- a version `SuperVersions::maintenance` pops has its memtables freed on
  a thread of its own (`lsm-release`), not under the version history's
  write lock ([why](UPSTREAM.md#issue-a-flushed-memtable-is-freed-under-the-version-historys-write-lock));
- `upgrade_version`, which a flush or a compaction calls, no longer
  publishes the new version's sequence number ([why](UPSTREAM.md#issue-a-flush-or-a-compaction-makes-a-write-batch-visible-in-part),
  the invariant the fix rests on, and its cost). Ingestion and fjall's
  meta-keyspace still publish it: the node uses neither while it writes.

**The tests' fix** (`src/time.rs`, compiled only for its tests): the clock
a test sets is per thread, not the process's. Tests run on parallel
threads, where a process-wide clock lets `fifo_ttl`'s (1,011 s) meet
`fifo_ttl_then_limit_additional_drops_blob_unit`'s (10,000,000 s), which
then finds both of its tables expired.

**What is ours:** those changes and that fix; `tests/released_versions.rs`;
`Cargo.toml` without the benchmarks the published crate leaves out, its
own `[workspace]`; `Cargo.lock` for its tests; and `UPSTREAM.md`.

**How it builds:** as published, with its own warnings (shown, not
denied: `-D warnings` applies to the workspace's members). Its tests run
in `just test`: `cargo test --manifest-path support/lsm-tree/Cargo.toml`.

**Removed** once a release of lsm-tree (with fjall) frees popped
memtables outside the version lock: then the patch entry goes, and this
directory with it.
