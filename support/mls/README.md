# vos-mls

An MLS layer ([RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)) over
[mls-rs](https://github.com/awslabs/mls-rs) 0.57 built with encrypted
handshakes alone, and RustCrypto's provider, for a group whose commits are
confirmed by its members before they take effect: each candidate is
processed on a copy, and only a confirmed one becomes the group's state.

## The model

- **One suite:** 1, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, the
  only one RustCrypto's provider is built with: a Welcome or a stored group
  naming another suite is refused as unsupported before any key is used.
  Every time is in seconds since the Unix epoch, as mls-rs counts.
- **Storage:** mls-rs's group-state and key-package storage providers over
  the caller's store (`Store`: read a committed row, list the committed
  keys under a prefix, commit a set of writes atomically and durably),
  each group's rows under a namespace's prefix (`Namespace`). Nothing
  mls-rs writes reaches the store by itself: a namespace stages its
  writes, and each operation commits them and the caller's own rows as one
  set of writes. The store is only handed keys of 1 to 65,535 bytes and
  values under 4 GiB: a key package is looked up only by a 32-byte
  reference, a Welcome into a group whose id is longer than 32 bytes is
  refused, and a commit holding any other row is an error
  (`Error::Unstorable`) that writes nothing. `MemStore` is a store in
  memory, for tests.
- **Copy and swap:** mls-rs applies a received commit at once, but a commit
  is confirmed only after it is processed. So a candidate (`Mls::process`,
  `Mls::join`) is processed on a copy of the group state, which reads the
  current rows and writes to memory alone, and is swapped in on
  confirmation (`Mls::swap`) or dropped. A candidate is bound to the state
  it was made from (the group's id and epoch, and for the member's own
  commit the commit held): swapped over any other, it is `Error::Stale`.
- **A member's own commit** (`Mls::commit`, `Mls::renew`) is built
  detached and held, in the same commit as the state it spent a key
  generation of. On confirmation it is applied on a copy (`Mls::own`) only
  if the confirmed candidate's handshake hash is the held commit's and the
  current epoch is the one before. A restart (`Mls::restart`) makes its new
  group at once, beside the current one, and holds its commit; `Mls::own`
  matches it by its handshake alone. A void deletes either (`Mls::void`),
  and so does the swap of any other candidate.
- **The policy:** an allow-list (Add and Remove by value in a commit with
  a path, a member's update as its own commit with a path; no ReInit,
  external commit, PSK or group-context change), its identities (64-byte
  basic credentials, the leaf's identity their first 32 bytes), and a
  candidate checked against the effect its caller expects (`Expected`):
  its committer, the credentials it adds and removes, exactly, and the
  credential its committer's leaf takes (the expected renewal, which is
  then required, or its own); the committer's leaf keeps its signature
  key.
- **The confirmation hash** (`confirmation`): Blake2b-256 over a domain,
  the group's 32-byte id as the caller names it, the epoch and the epoch's
  authenticator, which each member that processed the epoch's candidate
  posts, signed by its caller.
- **At rest:** every row is plaintext in the caller's store: the leaf's
  signing key, the group state (the epoch's secrets and private tree), key
  packages' private keys and a held commit (the whole next epoch). Only
  the current epoch is kept, but a deleted row may stay on disk as long as
  the store keeps it (a log-structured store until compaction). Protecting
  the disk is the caller's.

## Guarantees

- A failed operation writes nothing: the current state stays as the last
  commit left it. Two exceptions, both a failing store: a commit the store
  failed may be found written after a reopen, and an operation whose
  commit was written but whose group did not read back returns an error
  with the commit written.
- A candidate never writes through the current state before it is swapped
  in.
- A held commit survives a reopen and is matched only by its own handshake.
- A commit whose proposals are not its expected effect, or not allowed by
  the policy, is refused (`Error::Refused`).
- No bytes from a Welcome or a handshake make a key the store is not
  handed.

## Limits

- **A credential is a label.** It is 64 bytes whose meaning is the
  caller's; nothing binds a leaf's MLS signature or HPKE key to them. That a
  key package is the member's it names is the caller's to establish, and a
  committer allowed to add a member is trusted for the key package it
  adds: a compromised one can add a leaf of its own under another
  member's credential.
- **Clocks.** A key package is valid from an hour before its maker's clock:
  one whose maker's clock is more than an hour ahead of the committer's,
  or of the time a receiver and the joiner check it at, is not yet valid
  there.
- **A key package's year.** A key package is valid for 365 days, and a
  joiner checks every leaf that still comes from one: a member added over
  a year ago that has not committed since bars every new join until it
  commits.
- **1024 voided commits.** Each held commit spends a handshake-key
  generation of its epoch, also when voided; a receiver ratchets at most
  1024 ahead, so a member whose commits were voided more than 1024 times in
  one epoch is refused until another member's commit moves the epoch.
- **Features.** The crate's invariants assume mls-rs without `std`,
  `prior_epoch`, `out_of_order` or `by_ref_proposal`; Cargo unifies
  features, so no other crate in a build that uses this one may enable
  them.

## Tests

`cargo test -p vos-mls` (`tests/mls.rs`, over `MemStore` and a store whose
commits fail; each test's doc says what it shows). `just check` runs it.
