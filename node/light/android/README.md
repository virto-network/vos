# s4-credential

The `vos.credential` client facility: a member of a [VOS](https://codeberg.org/Virto/VOS)
space proves on its own device that it is a member (to sign in) or that it
holds a ledger account (to pay), and the s4 server that asked only relays what
the device made. The proofs are VOS's light node's device library's (`vos-light`); this
crate is the facility around it: the operations a server calls, the
trusted-chrome forms the user answers, the enrollment the device keeps, the
Tor client every request to a space goes through, and the device's personal
space.

It is an external facility (`vos.`, not `s4.`): a client build registers it and
the server registers it beside its built-in ones (`Server::facility`). The
client offers it only where the device has a secret source; on Android that
is Android 11 (API 30) or later.

## Operations

| operation | arguments | the chrome shows | answers |
|---|---|---|---|
| `enroll` | the space's handle and id, its agents with their identities, the methods the device may prove for (each its guard: `auth` with its scope and `once`, or `owner`), the credential actor's place, its onions (each with its SSH host key) and whether it is onion-only | all of it, to pin, and the source to use | the member's and the owner's digests |
| `sign_in` | a pinned auth method's agent, instance and name, and its arguments | the method, its scope and, for a `once` guard, that the call spends the member's one admission there | the node's answer to the `Credentialed` request the facility sent over Tor, and the proving time |
| `pay` | a pinned owner method (`transfer`), a payee's account and an amount | that it pays from this device's account; the payee and the amount in its own editable form | the node's answer to the transfer, encoded from what the user confirmed, and the confirmed values |
| `refresh` | none | nothing | the held path dropped, fetched again apart |

Every proof is a run of one of VOS's stock kernels, `auth` for a sign-in and
`owner` for a payment, proved under VOS's device format
(`vos_light::DEVICE_FORMAT`) against the program the kernel's release artifact
names, which the binding names too. The artifacts (`release/*.device`) are
built from the credential actor of the VOS revision this crate pins and
embedded in it (`Stock`); a server never sends a kernel, so the secret enters
only the stock kernels. `just vos-release VOS` writes them anew from a VOS
checkout at that revision. A proof takes up to about 0.7 GiB on a phone.

A stock kernel's program is computed once and kept while an enrollment's
guard proves with it: in the background, at a low priority, when the
facility opens (skipped on a device in power-save mode or low on battery),
at enrollment and at a session's grant. A sign-in waits for a program under way rather than
racing it, and one proof runs at a time. After a proof the heap's free pages
go back to the system: what stays is the programs and the pools.

A request naming a space, an agent or a method enrollment did not pin is
refused. Every text a form shows is checked free of control and bidirectional
formatting characters. The session's grant and each call's confirmation are
two prompts; the grant never stands in for a confirmation.

## Its own process

On Android the facility runs in the app's `:vos` process
(`android:process=":vos"`), which loads `libs4_credential.so`; the UI process
never does. The UI reaches it through one Binder interface, `IVosNode`
(`client/android/app/src/main/aidl/team/virto/s4/vos`), whose Rust form is
`s4-credential-contract`: the operations above by name, each with its typed
request and result, a refusal the operation's `out Refusal` (its code the
contract's `Code`), and nothing generic. A proved request never crosses:
the facility sends it over Tor itself, and only the node's answer goes back
to the server. A server's arguments are read
into an operation's request in the UI; the facility checks each request
again as it takes it off the interface (`src/node.rs`).

The prompts stay in the UI process: each operation is lent an `IVosPrompts`,
which shows the facility's forms in the client's trusted chrome and runs each
use of a secret source's key with the prompt that authorizes it
(BiometricPrompt and the Keystore's HMAC, or a security key's PIN and touch),
handing `:vos` only the result.

Besides the operations, the interface carries two background passes, each
its own periodic job in `:vos` with no UI (`src/job.rs`): `sync`, every
enrollment's tree read from its feed if due, and `syncPersonal`, the personal
space's pass at its agent. It carries the jobs' runs kept (`runs`), the
enrollments kept, Tor's bridges and the per-space opt-out, the personal
space's operations (`src/personal/`), and a byte stream (`openStream`) served
into one end of a Unix socket pair whose other end the UI holds as a
`ParcelFileDescriptor` (`src/stream.rs`: to a `.onion` over Tor, else a TCP
connection to the host the user named).

The UI binds while the app is started and for a minute after; it hands `:vos`
a token of its process, which `:vos` watches: when the UI dies or releases
the binding, every session it opened closes, and the tree's refresher stops
with the last.

## The personal space

The device's personal space (VOS's `light-node.md` §3): the light node under
`light/`, its group at the personal agent, and the flows the chrome drives:
the claim at a home-only space with a phrase or a security-key kit; pairing,
as the device that shows the code and as the one that scans it; the
memberships a pairing leaves (an enrollment owed, a confirmation); the
device set (remove, veto, cosign, resolve, rotate the kit, replace the admin
key, regroup, a commit now); the yearly re-proof; a restore from the kit; a
move home. Each admin call is signed by the admin key, an Ed25519 key in the
UI's Keystore behind a strong biometric (`IVosPrompts.signKey`). The light
node's artifacts (`release/agent.program`, `release/*-book.package`) are
embedded, and `tests/programs/personal.package` is the personal agent the
tests run in process; `just vos-release VOS` writes them all. A local actor
installed at an earlier release than the app carries is upgraded in place.

What the device keeps beside the light node is `personal.state`, versioned:
a file or a store this build does not read is refused and left as it is,
the personal space named in need of repair, sign-in and payments unaffected.
Each flow keeps its keys the moment it makes them, and the home and agent it
goes to before the call that makes it so: `:vos` killed at any step leaves a
flow that the same call resumes (a claim, a restore, a move: no new kit, no
second agent) or the background job finishes (a pairing's acknowledgement, a
move's carry, the credential book's records). `tests/crashes.rs` kills it at
each request of each flow. A device paired in enrolls in each offered space
with the key its handle there came from.

## Tor

One arti runtime in `:vos`, its state in `files/tor` (outside every backup),
bootstrapped at start, through the bridges pasted in the chrome when the
network blocks Tor. Every request to a space goes through one client, over
the onions enrollment pinned, under its purpose: each proof on a circuit of
its own, the tree's feed, the node's time, the personal agent's traffic
(what the user does, and the job's, apart). The clearnet is used only for a
space whose key-signed calls the user opted out of Tor, never for a proof
or the personal space. The client is dormant while the app is in the
background, and woken around each job.

Either process may die without the other: the UI's death leaves an operation
running to its end in `:vos`, its answer dropped; `:vos`'s death fails the
operation under way in the UI, and the next opens its session again in a new
`:vos`. Every write of the store is whole or nothing (`tests/killed.rs` kills
the facility's process during proofs and syncs).

## What the device keeps

Per verified SSH host key and application: the secret source's reference (the
Keystore key's alias, or a security key's credential id), what enrollment
pinned, the gateway it was made through, and the member digest (the public
leaf whose path the device keeps).
The secret is derived again at each use from the source's output and dropped
once the proof is made; the output is zeroized once copied.

## The tree and time

Each enrollment's tree is read from its credential actor's feed on a jittered
timer while a session is open, never because a proof is about to be made,
and kept beside the enrollment (`<enrollment>.tree`), so a restart reads only
the changes since; a root the node no longer holds makes the feed due at a
drawn delay. The node's time is read before an expiry is picked.

## Building

VOS's prover needs its own nightly, pinned in this directory's
`rust-toolchain.toml`; the crate is outside s4's workspace so the stable gate
never builds it. `just vos` (from the repository root) lints and tests it, and
`just android-build-vos` builds the APK with it beside the client's library,
for the `:vos` process to load.

License: AGPL-3.0-or-later.
