# vos-light: security considerations

What the light node's local agent keeps, and what the device library
holds, what it exposes the member's secret to, and what it leaves to the
client that links it. It is descriptive, not a
formal argument. The design is `docs/design/proving.md` §8 (the
derivation, the statements, the library) and
`docs/design/identity-and-authority.md` §7 (the in-space credential's
threat model); what a verified proof proves is `pvm/proof/SECURITY.md`'s,
and what a node does with one is `node/SECURITY.md`'s.

## The local agent

- **Its programs are the app's:** the agent program and each local
  actor's programs are release artifacts the app embeds
  (`light-node.md` §4.4); an install checks each program's hash against
  the derivation it names, and the phone runs no transpiler.
- **Its store is plaintext on the device:** the local agent's rows, its
  programs, its scopes' nodes, its last local operation's time and seed,
  and its author key (the ed25519 seed its scopes' nodes are signed with),
  in a fjall database under the directory the client names. The client
  keeps it in the app's private storage; sealing what leaves the device
  is sync's, not the store's.
- **Its author key is the store's:** drawn from the operating system when
  the store is made, never copied out of it, so a new install or a
  restore signs as a new author and a backup never reuses a sequence
  number under an old key, provided the store is never restored from a
  copy: the client keeps its directory out of the operating system's
  backup (Android's auto-backup and device transfer), as a copy restored
  would sign again at numbers it already signed, equivocate, and be cut
  off. Whoever reads the store can sign as it in its scopes until the
  device set removes it.
- **Each operation is one synced batch:** a process killed at any point
  leaves the store before the operation or after it, never between, a
  scope's nodes with the rows they wrote; the store is mended at open as
  a node's is (`vos_exec::store::recover`), and one written in another
  layout is refused.
- **A local call is a merge handler's operation:** the merge entry runs
  `#[msg(merge)]` handlers alone, writing their merge fields alone and
  reading no row, and records nothing for a handler that fails. A peer's
  node is applied only if its author signed it for the scope, and its
  operations run through the same entry, so a peer reaches only what a
  merge handler writes; an operation whose run fails writes nothing, and
  one this build cannot run (an unknown kind or method, a run that
  faults) is held, so no node stops the scope's sync. Validation of what
  a well-formed operation writes, and quarantine, are not built
  (`light-node.md` §8, C1).
- **Reads filter, never unapply:** an author that equivocated, and one
  the client cuts off (a removal past its frontier), are filtered when a
  merge field is read, from their cutoff on; their rows stay. A field
  keeps one entry an element and author, its latest: a cut-off author's
  write past its cutoff hides its own earlier write to that element,
  which reads then fall back from to the other authors'.

## The secret and its containment

- **The source** is a keyed HMAC-SHA-256 whose key the device never
  exports: an Android Keystore HMAC key, user authentication at every use
  (a biometric or the PIN through `BiometricPrompt`), StrongBox-backed when
  the phone has it; or a security key's `hmac-secret` over CTAP2, always
  with its PIN and a touch. The client's bridge evaluates it, once a use,
  on `source_input(handle)`; the library never sees the key.
- **The output `o` is the secret.** Anyone holding `o` and the space's
  public handle derives `s` (`derive_secret`), for good. `o` crosses into
  the app's process at each use, as the `byte[]` `Mac.doFinal` returns (or
  YubiKit's answer): the bridge zero-fills it once the library has copied
  it, and the caller zeroizes its Rust copy once `derive_secret` returns.
- **What the library zeroizes:** the derivation's 64-byte `w` and each
  wide word; `DeviceSecret` on drop (no `Clone`, no `Debug`); the
  nullifier's key `C(T(nf), s)`; a kernel's arguments (the secret's
  bytes and the path) once its run is proved.
- **What it does not:** a kernel's traced run (its witness pages,
  registers and memory ledger, which hold the secret's bytes) and its
  main trace, the prover's trace and its masked polynomials,
  which hold the secret's words and every value derived from it, are
  freed with the proof's other buffers, not overwritten; so are BLAKE2b's
  and the Poseidon2 permutation's internal states, and copies the
  compiler leaves on the stack or in registers. A heap or a core dump read
  during or after a use may hold them. The protection is the process's:
  code in the app's process during a use (a compromised dependency, a
  debugger on a debuggable build, a rooted phone) reads `o`, and with it
  `s`.
- **Consent at every use:** a use takes the user's consent at the source,
  so malware cannot evaluate it silently, but one use is enough to keep
  `s`.
- **A lost key is a lost `s`:** the key is bound to the phone (or to the
  security key), not to an account; nothing syncs it. A factory reset, a
  screen lock removed or a lost security key loses `s`: the member is
  revoked and enrolls again, and the ledger's `rekey` moves its rows.
- **What `s` gives a thief:** auth as its member in every scope of the
  space (and of any space sharing its handle), payment from every row
  `owner(s)` owns, and every nullifier the member has used or will use.
  Revoking the leaf stops auth within `ROOT_MAX_AGE`; it does not stop
  payment: the ledger's `rekey` and `freeze` do.

## What the library shows

- **No logging of witnesses:** it logs nothing. `DeviceError` names what
  failed and carries no value: no secret, path, word or proof byte.
- **No seeded masks in a production build:** a proof's masks are the
  operating system's, and no configuration chooses otherwise. The one
  seam is the library's `seeded-masks` feature (`Prover::seeded`), which
  the phone bench's seeded build turns on so its proofs' bytes can be
  compared with x86's; `just check-no-seeded-masks` refuses it in the
  library's default build and in every production build.
- **`AuthWitness`'s `Debug` shows nothing** of its root, slot or
  siblings, which place the member's leaf.
- **A proof's shape is the program's:** every chip pads to its log size
  in the release, and the stock auth kernel walks its path with selects,
  so its rows do not depend on the slot or the secret.

## The witness and the call

- **`prove_auth` checks its witness first:** a path that does not place
  `member(s)`'s leaf under its root is `Witness`, before any proving; the
  prover refuses a witness word at or above p.
- **The scope and the binding are computed here** from the `Call` and the
  guard's name, so a client never assembles them; the binding names the
  space, agent, instance, method, the kernel's program, the arguments,
  the nonce and the expiry, and the claim carries it last. `Call::new`
  draws the nonce from the operating system.
- **The claim is computed here** from the secret, the witness and the
  call, and the proof is checked to state its io-hash before it is
  returned.

## Paths, and what fetching them shows

- **Paths are fetched apart from proofs** (`PathKeeper`): on a jittered
  timer, and within a spread of up to 10 s after a moved `root()` is
  first seen, never because a proof is about to be made; each `path` or
  `root()` query is signed by a key drawn for it alone. The keeper only
  says when: **the client** polls `root()` on a jittered timer of its own
  and sends the queries on a connection of their own, apart from the one
  that carries its proofs. `node/SECURITY.md` states what the fetches
  still show the operators.
- **`verify`** runs ingress's checks that need neither a clock nor
  state; the expiry window, the root's freshness and replay are the
  node's.
- **A `RootUnknown` (or `RootStale`) answer** drops the held path: the client fetches it
  again and proves anew. That one fetch precedes a proof, so its time
  links to the proof's; it happens only when the ring no longer holds the
  root (a replica's lag, a root replaced at its own batch time, or 64
  tree-changing batches within the keeper's period).
