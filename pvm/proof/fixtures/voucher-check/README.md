# Voucher-check release fixture

`catalog.toml` is parsed through the production catalog API. Its `blob_hash`,
canonical profile, and program commitment describe the exact published
voucher-check PVM, not whichever candidate happens to build from the current
checkout.

`voucher-check.pvm.gz` is that exact PVM, stored compressed to keep the opaque
fixture under 180 KiB. The ordinary, non-ignored
`voucher_check_catalog_commitment_matches_current_air` test embeds and
decompresses it, checks its content identity against `catalog.toml`, and
remeasures the profile-bound AIR commitment. A missing fixture is therefore a
compile failure and a corrupt or stale fixture is a test failure; a clean
checkout cannot skip the gate.

Run the same gate used by pre-push and production packaging with:

```sh
just verify-voucher-check-release
```

The source project remains useful for smoke tests and future releases, but a
source build is never an implicit production repin. The ignored
`voucher_check_current_source_candidate_matches_published_release` maintenance
test compares a freshly built candidate with the published PVM. At this
cutover, the candidate has blob hash
`161de13f47cb8e72ebb5aa7583eb8ab35b68c4ed28042021716a02067661a19b`,
while the published pin is
`5866fc11e48309aa97d87ce6c6c8469088a88c484a4f7fb9691c7c82fc50dd55`.
Closing that provenance drift requires an explicit, reviewed artifact and
catalog repin; it is intentionally outside this release-gate fix.
