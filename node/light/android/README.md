# vos-facility

The `vos.credential` client facility for [s4](https://codeberg.org/Virto/s4):
a member of a VOS space proves on its own device that it is a member (to sign in) or that it
holds a ledger account (to pay), and the s4 server that asked only relays what
the device made. The proofs are VOS's light node's device library's (`vos-light`); this
crate is the facility around it: the operations a server calls, the
trusted-chrome forms the user answers, the enrollment the device keeps, the
Tor client every request to a space goes through, and the device's personal
space.

It is an external facility (`vos.`, not `s4.`): s4's client hosts it behind
s4's credential contract (`s4-credential-contract`, its Binder interface
and its UI side, which s4 keeps), and the server registers it beside its
built-in ones (`Server::facility`). The client offers it only where the
device has a secret source; on Android that is Android 11 (API 30) or
later. This crate depends on s4's crates by git revision; s4 depends on
nothing of VOS.

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
built from this tree's credential actor and embedded in the crate (`Stock`);
a server never sends a kernel, so the secret enters only the stock kernels.
`just facility-release` writes them anew, and `tests/release.rs` fails while
they are not this tree's guests'. A proof is allowed the device budget,
`vos_light::PEAK_BYTES` (1 GiB).

A stock kernel's program is computed once and kept while an enrollment's
guard proves with it: in the background, at a low priority, when the
facility opens (skipped on a device in power-save mode or low on battery),
at enrollment and at a session's grant. A sign-in waits for a program under way rather than
racing it, and one proof runs at a time. After a proof the heap's free pages
go back to the system: what stays is the programs and the pools.

A request naming a space, an agent or a method enrollment did not pin is
refused. Every text a form shows is checked free of control and bidirectional
formatting characters. The session's grant and each call's confirmation are
two prompts; the grant never stands in for a confirmation. A reconnect s4
makes by itself keeps the grant of the session it replaces, in s4's memory:
the facility's session on it is new, knowing nothing of the one before. A
sign-in and a payment report their stages to the chrome ("Proving…",
"Sending…"); the digests show as a code and a six-digit check
(`vos_api::enrollment_code`, `enrollment_check`).

## Its own process

On Android the facility runs in the app's `:vos` process
(`android:process=":vos"`), which loads `libvos_facility.so`; the UI process
never does. It serves two Binder interfaces. s4's client reaches it through
`IVosNode` (s4's `credential-contract/aidl/team/virto/s4/vos`), whose Rust
form is `s4-credential-contract`: the operations above by name, each with its
typed request and result, a refusal the operation's `out Refusal` (its code
the contract's `Code`), and nothing generic. A proved request never crosses:
the facility sends it over Tor itself, and only the node's answer goes back
to the server. A server's arguments are read into an operation's request in
the UI; the facility checks each request again as it takes it off the
interface (`src/node.rs`). The facility's own screens reach it through
`IVosPersonal` (`aar/src/main/aidl/team/virto/vos/personal`, bound by the
intent action of that name), whose Rust form is `src/personal/contract.rs`;
both interfaces' parcelables are declared once with s4's `parcel!`, held to
their AIDL in `cargo test` and round-tripped on a JVM
(`just facility-contract`, s4's `just android-contract`).

The prompts stay in the UI process: each operation is lent an `IVosPrompts`,
which shows the facility's forms in the client's trusted chrome and runs each
use of a secret source's key with the prompt that authorizes it
(BiometricPrompt and the Keystore's HMAC, or a security key's PIN and touch),
handing `:vos` only the result.

`IVosNode` also carries the jobs' runs kept (`runs`), the enrollments kept,
and s4's screens (`screens`): s4's SSH bytes between the UI's end of a Unix
socket pair and a gateway, over the routes of the space enrolled through it
with the host key it pinned, or, for an onion service no space pins, over Tor
with no key pinned (`src/stream.rs`), the client's known hosts deciding it.
`:vos` opens no TCP connection to a host the user named. `IVosPersonal`
carries the two background passes, each its own periodic job
in `:vos` with no UI (`src/job.rs`): `sync`, every enrollment's tree read from
its feed if due, and `syncPersonal`, the personal space's pass at its agent;
Tor's bridges and the per-space opt-out; the personal space's status
(`status`: its phase, a restore's maturity, Tor's state, the memberships owed,
the notices standing, what needs repair, the kind of kit a kit's call enters,
why the last pass did not finish), which the screens branch on; the screens'
watcher (`watch`: each flow's stage and each pass's end); the restore screen's
sitting (`kitHold`, `kitForget`: the kit entered once and held in `:vos` for
its flows, ten minutes at most, wiped when the screen closes or the app goes
to the background); and the
personal space's operations (`src/personal/`, called as
`node.personal()?.claim(..)`), each refusing with a `Refused` of its `Why`
(`vos_light::space::Error`'s kinds), worded by the screens' `Words`. Every
native
method is one entry of `src/android.rs`'s `natives!` table, which
`cargo test` holds the Java `native` declarations to. A debug build's probe
runs from a shell through s4's `VosProbe` (`am instrument -w -r -e op sync -e
count N team.virto.s4/.VosProbe`, or `-e op personal`): the ops it does not
know it hands to this library's `Probe` (s4's `FacilityProbe` hook, named in
the AAR's manifest), which runs them over `IVosPersonal`.

The UI binds while the app is started and for a minute after; it hands `:vos`
a token of its process, which `:vos` watches: when the UI dies or releases
the binding, every session it opened closes, and the tree's refresher stops
with the last.

## The personal space

The device's personal space (VOS's `light-node.md` §3): the light node under
`light/`, its group at the personal agent, and the flows the chrome drives: the
claim at a home-only space with a phrase or a security-key kit; pairing, as the
device that shows the code and as the one that scans it; the memberships a
pairing leaves (an enrollment owed, a confirmation); the device set (remove,
veto, cosign, resolve, rotate the kit, replace the admin key, a regroup keeping
this device alone, a commit now); a restore from the kit; a move home (leave,
claim at the new home; the other devices pair again from it, leaving the space
they held). Each admin call is signed by the admin key, an Ed25519 key in the
UI's Keystore behind a strong biometric (`IVosPrompts.signKey`). The light
node's artifacts (`release/agent.program`, `release/*-book.package`) are
embedded, `just facility-release` writes them with the stock kernels', and the
tests run this tree's personal agent in process (`vos_testkit::personal`), its
user and phone the shared `Phone` (`vos_light::testing`, this crate's
`testing` feature). A local actor installed at an earlier release than the app
carries is upgraded in place.

The flows are `vos_light::space`'s, over a `Host` and a `Prompts`; this crate is
their adapter (`src/personal/`): the contract's types, `Refused`, the forms'
words. What the device keeps of its personal space is rows of the light node's
store (`p/…`), each written in the batch of the group change it describes: a
store this build does not read is refused and left as it is, the personal space
named in need of repair, sign-in and payments unaffected. What the facility
keeps apart from it (its enrollments, each space's routes, the bridges, the
jobs' runs) is rows of its own fjall database under `facility/`
(`src/kept.rs`), each SCALE of a facility-owned type, its layout checked at
open: a database of another layout is refused and left as it is, a row that does
not decode is an error, never a default. The credential trees and the
rendezvous tally stay files. Each flow keeps its keys the moment it makes them:
`:vos` killed at any step leaves a flow that the same call resumes (a claim, a
restore, a move: no new kit, no second agent) or the background job finishes (a
pairing's acknowledgement, the credential book's records). Leaving a personal
space (a move, a pairing from another one) makes the light node's store anew
under `light.<n>`, made the device's by its first batch, the old store deleted
after. `tests/crashes.rs` kills it at each request of each flow. A phone of an
earlier build (light `LAYOUT` 9 or before, or enrollments as TOML files) clears
the app's data and claims or pairs again, and enrolls again. A device paired in
enrolls in each offered
space with the key its handle there came from.

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
timer while a session is open, not because a proof is about to be made (but a
sign-in with no path yet reads it every 5 s for up to a minute, waiting for the
operator's invitation), and kept beside the enrollment (`<enrollment>.tree`),
so a restart reads only the changes since; a root the node no longer holds makes the feed due at a
drawn delay. The node's time is read before an expiry is picked.

## Building

The crate is outside VOS's workspace: s4's crates ask a newer Rust than the
workspace's nightly, which builds them with `--ignore-rust-version`. From
the repository's root:

- `just test-facility`: its lints and its suites with the `android`
  feature, the release artifacts held to this tree's guests among them,
  every s4 revision VOS names held to one (`tests/pin.rs`), and the
  JVM round trip when the SDK and a JDK are here (part of `just gate`);
- `just pin-s4 <rev>`: s4 pinned at another revision in every manifest
  and lockfile that names it;
- `just facility-release`: the release artifacts written anew;
- `just android-facility [out]`: the Android library (`aar/`,
  `team.virto.vos:facility`) published to the local Maven repository
  `out` (`target/android/maven`): the `:vos` process (`team.virto.s4.vos`,
  the package of s4's interface it serves), the personal space's screens and
  their interface (`team.virto.vos.personal`) and
  `libvos_facility.so` for ARM64, compiled against the credential
  contract's UI side of the s4 checkout this crate names. s4's
  `just android-build-vos <out>` then builds the APK with it.

License: AGPL-3.0-or-later.
