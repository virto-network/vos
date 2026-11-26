# vmls

[MLS](https://www.rfc-editor.org/rfc/rfc9420) groups, over
[mls-rs](https://github.com/awslabs/mls-rs) 0.57, in which **a change only
counts once the members confirm it.**

In MLS a group shares a secret. Every join, leave or key refresh is a
*commit* that starts a new *epoch* with a new secret. mls-rs applies a
commit as soon as it arrives. That fails when the members must first agree
on which commit wins, for example when two commit at once. vmls tries each
commit on a copy and keeps it only once you say it was confirmed.

## When to use it

- Your members, or a service in front of them, decide the order of commits,
  and every member must end on the same epoch.
- The group state must live in your database and be written in one atomic
  batch with your own rows.

It covers membership and keys only, not messages: derive keys from the
epoch's secret with `Mls::export`. It supports one suite (1: X25519,
AES-128-GCM, SHA-256, Ed25519), with no external commits, PSKs or ReInit.

## How it works

```text
 received commit ──► process ──► Candidate (a copy)
                                    │  confirmed?
 epoch n ─────────── swap ◄─────────┘ ──► epoch n+1
                     (not confirmed: drop it, nothing changed)
```

- **Others' commits:** `Mls::process` (a commit) and `Mls::join` (a Welcome)
  give a `Candidate` on a copy. `Mls::swap` makes it current. A candidate
  made before the group moved on is `Error::Stale`.
- **Your commits:** `Mls::commit` builds one and holds it until confirmed.
  `Mls::own` then gives its candidate. `Mls::void`, or swapping in any
  other candidate, drops it. `Mls::renew` also changes your credential, and
  `Mls::restart` starts a new group beside the current one.
- **Checks:** a received commit must make exactly the change you expect
  (`Expected`: who commits, who is added and removed, any new credential)
  and use only Add, Remove or the committer's own update. Otherwise it is
  `Error::Refused`.
- **Confirming** is yours: members who processed the same commit get the
  same `Candidate::authenticator`. It names no group or epoch, so sign it
  under your own domain together with the group id and the epoch. A member
  the commit removes gets none.
- **Storage:** you implement `Store` (read a row, list a prefix, write a
  batch atomically), or use `MemStore` in tests. Each group lives under a
  `Namespace` prefix, and every call that changes state writes your rows
  (`Writes`) in the same batch.

## Guarantees

- A failed call writes nothing, unless the store itself fails: a batch it
  reported as failed may turn up after a reopen, or a written batch whose
  group did not read back returns an error.
- A candidate never touches the current state before its swap.
- A held commit survives a reopen and matches only its own bytes.
- The store only sees keys of 1 to 65,535 bytes and values under 4 GiB. A
  received message can't make another key, and a row of yours outside the
  bounds is `Error::Unstorable`, with nothing written.

## Limits

- **A credential is a label** (64 bytes, meaning yours). Nothing ties a
  member's MLS keys to it: checking that a key package belongs to the member
  it names is your job. A compromised member who may add others can add a
  key of its own under another member's credential.
- **Secrets are stored in plain text** in your store. Only the current
  epoch is kept, but deleted rows may stay on disk until the store compacts.
- **Clocks:** times are Unix seconds you pass in. A key package is valid
  from an hour before it was made, for 365 days. One made by a clock more
  than an hour ahead isn't valid yet elsewhere. A member whose key package
  is over a year old blocks new joins until it commits again.
- **Voided commits:** past 1024 voided commits of its own in one epoch, a
  member is refused until another member's commit moves the epoch.
- **mls-rs features:** vmls needs mls-rs without `std`, `prior_epoch`,
  `out_of_order` and `by_ref_proposal`. Cargo merges features, so no other
  crate in the build may enable them.

## Tests

`cargo test -p vmls` runs `tests/mls.rs` over `MemStore` and a store whose
writes fail. Each test's doc says what it shows.
