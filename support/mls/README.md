# vos-mls

VOS's one MLS layer ([RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)),
over [mls-rs](https://github.com/awslabs/mls-rs) 0.57 built with encrypted
handshakes alone, and RustCrypto's provider. Its first user is a user's
device group: the devices that hold one personal agent's keys
(`docs/design/light-node.md` §3.4 on the `vos-core` branch); member
messaging comes later.

## The model

- **One suite:** 1, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`. Every
  time is in seconds since the Unix epoch, as mls-rs counts.
- **Storage** (`storage`): mls-rs's group-state and key-package storage
  providers over one fjall keyspace, each group's rows under a namespace's
  prefix. Nothing mls-rs writes reaches the disk by itself: a namespace
  stages its writes, and `Store::commit` writes them and the caller's own
  rows in one synced batch.
- **Copy and swap:** mls-rs applies a received commit at once, but a commit
  is confirmed only after it is processed. So a candidate (`Mls::process`,
  `Mls::join`) is processed on a copy of the group state, which reads the
  current rows and writes to memory alone, and is swapped in on
  confirmation (`Mls::swap`) or dropped.
- **A device's own commit** (`Mls::commit`, `Mls::renew`) is built
  detached and held, in the same batch as the state it spent a key
  generation of. On confirmation it is applied on a copy (`Mls::own`) only
  if the confirmed candidate's handshake hash is the held commit's and the
  current epoch is the one before. A restart (`Mls::restart`) makes its new
  group at once, beside the current one, and holds its commit; `Mls::own`
  matches it by its handshake alone. A void deletes either (`Mls::void`).
- **The policy** (`policy`): the device group's allow-list (Add and Remove
  by value in a commit with a path, a device's update as its own commit
  with a path; no ReInit, external commit, PSK or group-context change),
  its identities (64-byte basic credentials), and a candidate checked
  against the effect its log entry declares (`Expected`): its committer,
  and the credentials it adds and removes, exactly.
- **The confirmation hash** (`confirmation`): Blake2b-256 over a domain,
  the agent, the epoch and the epoch's authenticator, which each device of
  the confirming set posts, signed by its caller.

## Guarantees

- A failed operation writes nothing: the current state stays as the last
  batch left it.
- A candidate never writes through the current state before it is swapped
  in.
- A held commit survives a reopen and is matched only by its own handshake.
- A commit whose proposals are not its declared effect, or not allowed by
  the policy, is refused (`Error::Refused`).

## Tests

`cargo test -p vos-mls` (`tests/mls.rs`, over a fjall store in a temporary
directory): a group of three moved through commits held and confirmed on
copies; a copy leaving the current state as it was; a held commit across a
reopen, matched by its handshake and deleted on a void; a candidate refused
unless it is its logged effect exactly (committer, adds, removes); the
policy refusing what it does not allow, from a member running other rules;
the confirmation hash moved by each of its parts; a restart into a new
group; a leaf's credential renewed only as expected. `just
check` runs them.

## Users

On the `vos-core` branch: the light node's device group
(`node/light/src/group.rs`, `node/light/src/group/follow.rs`), its store
(`node/light/src/store.rs`) and its tests (`node/light/tests/group/`).
