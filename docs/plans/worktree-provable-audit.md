# `worktree-provable` disposition

This records the explicit audit of the rescued branch
`rescue/worktree-provable-20260722` (tip `f9d701a9`) against the reviewed v2
production line. It is a provenance record, not a branch to merge. The old
commits are not patch-identical to master because their useful behavior was
reworked behind the current service guest, storage, privacy, proof, and
production-trust contracts.

| Rescued work | Disposition in the reviewed line |
|---|---|
| `4c327339` WitnessedLedger primitive | Landed in the authenticated point-storage/witness model (`vos/src/zk/state.rs`, `vos/src/actors/storage`, Batches 63–64). |
| `cc415b3c`, `b2aff015`, `10176157` durable record capture and verification | Replaced by bounded producer-private records, commitment-only private ingress, restart reconciliation, and production proof verification (Batches 41, 57, 60–64). The old effect-log secret representation must not be restored. |
| `d0598ed7`, `08f48cf` Clerk Task and batch-proof integration | Landed through canonical signed Task dependencies, exact Refine traces, software-arithmetic Clerk packages, ledger delegation, and production cutover (Batches 42, 58–60, 63). |
| `57b7c061` precompile-backed live Tasks | Deliberately rejected. The crypto ECALL outputs were not AIR-constrained; production Clerk/voucher programs use software arithmetic until that proof boundary exists. |
| `8bc88ae5`, `c02d00b3` registry pagination/name validation | Landed in Batch 43 with corrected Option wires, refreshed artifacts, and CRDT-scoped message-log tests. |
| `69059a09` example relocation | Landed in the public/test-only example split in Batches 31 and 44. |
| `f9d701a9` integration-state snapshot | No independent feature remains. Its storage/proof/Clerk pieces are covered by the rows above; its obsolete runtime integration would regress current guest-owned Accumulate and privacy boundaries. |

`git cherry master rescue/worktree-provable-20260722` still reports several
`+` patches because the replacements are structural rather than cherry-picks.
That is expected and is not an outstanding-work signal. Future work should
start from master and the roadmap, using the rescued tip only as historical
design input. In particular, the remaining CRDT-private-Task protocol and
proof-constrained crypto precompiles are explicit future slices, not missing
branch integration.
