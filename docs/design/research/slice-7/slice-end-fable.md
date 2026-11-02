# Slice 7's slice-end review (Fable)

Read-only, at `vos-core` `88fc26e18`, 2026-11-01. **Verdict: accept after
listed fixes.** No Critical or High defect in the code; the two Highs were
the acceptance record's.

## Findings and their folds

| finding | what | fold |
|---|---|---|
| H1 | the final AIR (formats 41, 46) had no full gate | the slice gate at `2a163b274`: `slice-gate` (leakage N = 2000, fuzz 300 s a target), release names, `check-blobs`, `e2e-chain`, the checker loop (seeds 7951–7962), each `exit=0` |
| H2 | PG2 unmeasured on format 46 | P8: 645 ms, accepted at ingress 9 of 9 |
| M1 | S50's run 3 over the node API unrecorded | `scale-report.md`, "Run 3 on the final build": p99 1.31 s (2.6 s before) |
| M2 | a replayed signed `Install` decoded before its nonce check | refused after the signature, before the decode (7.23d) |
| M3 | a `peer_lanes` mismatch partitions a node silently | the heartbeat carries the lanes; a peer whose lanes differ refused loudly (7.23d; a peer-protocol change) |
| M4 | the logged `map_root` a cross-scope fingerprint | stated in `node/SECURITY.md` and `identity-and-authority.md` §7; the fix carried |
| M5 | s4's leak fixes unpushed | resolved: on s4 `vos` (`7de206e`, then `5c5a018`) |
| M6 | the PG3 demo binary holds the operator's key | stated in `node/SECURITY.md` and the PG3 record |
| M7 | the sub-millisecond wrong-PoW refusal measured on 44 only | format 46 measured (wrong PoW 8.0 ms, verified 11.7 ms); bounds per format in `node/SECURITY.md` |
| M8 | the 17-page step cap enforced only at proof time | `derive` refuses a prologue's step past the largest class (`DeriveError::StepPages`) |
| M9 | no Fable review of 7.16's parameters, 7.20, C10 | reviewed: all three sound; their lows folded (7.23d) |
| L1–L11 | the operator floor, `RootUnknown` without a batch time, the program cache's errors, one panic guard, `Once`'s order documented, QUIC stream deadlines, an atomic place count, one `Installed` decode, s4's honoured refresh, stale records | folded (7.23d), except L6 (the binding sweep's budget, a consensus rule in refine), carried |

## Carried to the next slice

S55 (the executors' bound on compumax); T1's and T6's p99 and T5's
throughput (the shared disk, the commit-to-apply gap, batched signature
checks: S59's levers 4–6); T2 and T5's host kill (more machines); the
per-program CPU and word-level memory (S63); the per-call identity read;
the identity agent replicated per node; the non-repudiation side store;
tree syncing (the path leak) and the `map_root` fingerprint (M4); 7.9's
quiet re-measure of `0x402`; the binding sweep's budget (L6); reproducible
path-dependent blobs (S58); the heavy cleanup before master; the external
audit's scope (the credential AIR, the device shape, the Poseidon2 chip,
their masking).
