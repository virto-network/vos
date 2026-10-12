# To file upstream (fjall-rs/lsm-tree, and fjall)

A draft issue, and two ways to fix it, for the owner to file.

## Issue: a flushed memtable is freed under the version history's write lock

**Versions:** lsm-tree 3.1.10, fjall 3.1.12.

**What happens:** `SuperVersions::maintenance` pops the versions below the
gc watermark while its caller holds `version_history.write()`. A popped
version can hold the last reference to a flushed memtable, so the whole
skiplist is freed inside the lock, and every `get`, range and insert on
the tree waits for it.

**Where:** lsm-tree calls `maintenance` in `Tree::register_tables` (a
flush) and in the compaction worker's merges, moves and drops. fjall calls
it in `Keyspace::inner_rotate_memtable`, on every keyspace, after
`snapshot_tracker.pullup()` and `gc()`:
`keyspace.tree.get_version_history_lock().maintenance(..)`. Since the
watermark moves up there, that is where most flushed memtables lose their
last reference.

**How long:** freeing a 64 MiB memtable (the default) takes 100–160 ms on
a laptop (x86-64, glibc). Sampling a loaded process shows its readers and
writers all stopped for that time while one fjall worker runs
`drop_in_place<Vec<Arc<Memtable>>>`.

**Reproduction:** `tests/released_versions.rs` here. A tree is flushed
with watermark 0, so the versions holding its memtable stay. A small
flush with every version below the watermark then pops them while a
thread times `get`s. Unpatched, a read waits as long as the free (97 ms
against 96 ms, debug build).

## Two ways to fix it

**(a) Callers drop what `maintenance` pops, after their locks.**
`maintenance` returns the popped versions (`#[must_use]`), and every
caller drops them once it has released `version_history` (and
`compaction_state`, which flushes take too). That includes fjall's
rotation loop: collect each keyspace's popped versions, and drop them
after the `keyspaces` read guard. It needs a change in fjall too.

**(b) lsm-tree frees popped memtables on a thread of its own.** This is
the patch here: `maintenance` keeps its signature, and sends a popped
version's memtables to a thread that frees them. Tables are dropped where
they are popped, so a deleted table's file is removed when it always was.
No caller changes.

## Also worth considering

- **The syncs under the same lock:** `upgrade_version` syncs the new
  version file, its directory and `CURRENT` under the write lock, five
  syncs at every flush and compaction. They could be prepared before the
  lock is taken, leaving only the rename under it.
- **Table ids across a reopen:** recovery starts the table-id counter at
  the highest live table's id plus one, after removing orphaned files. A
  deleted table still referenced in memory across a reopen in the same
  process (by a long-lived snapshot, or a drop deferred) removes its file
  when it is finally dropped, and that file is the new table's if its id
  was reused. Never reusing an id within a process (a counter above every
  id it has seen) would rule that out.
