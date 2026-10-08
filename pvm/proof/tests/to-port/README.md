# Tests waiting to be ported

These tests ran under the JAR profile and depended on crates that left this
branch. Slice 1, step 1.2 ports them to the Gray Paper profile and moves them
back into `tests/`. Nothing here is compiled until then.

- `voucher_check_smoke.rs`: used `vos::zk` for catalog parsing and task-blob
  hashing.
