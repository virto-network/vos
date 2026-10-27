# vos-device: security considerations

What the device library holds, what it exposes the member's secret to, and
what it leaves to the client that links it. It is descriptive, not a
formal argument. The design is `docs/design/proving.md` §8 (the
derivation, the statements, the library) and
`docs/design/identity-and-authority.md` §7 (the in-space credential's
threat model); what a verified proof proves is `pvm/proof/SECURITY.md`'s,
and what a node does with one is `node/SECURITY.md`'s.

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
  nullifier's key `C(T(nf), s)`; the secret's words in the circuit's
  statement after each proof, a panic unwinding included; the circuit's
  private values (every row of the witness but its public outputs) once
  the prover has taken them.
- **What it does not:** the circuit builder's own copy of the values
  (recair's `Context`), the prover's trace and its masked polynomials,
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
- **A proof's shape is the statement's:** every component pads to the
  masking's floor, and the auth circuit walks its path with selects, so
  its rows do not depend on the slot or the secret.

## The witness and the call

- **`prove_auth` checks its witness first:** a path that does not place
  `member(s)`'s leaf under its root is `Witness`, before any proving; the
  prover refuses a witness word at or above p.
- **The scope and the binding are computed here** from the `Call` and the
  guard's name, so a client never assembles them; the binding names the
  space, agent, instance, method, the statement's program and kind, the
  arguments, the nonce and the expiry. `Call::new` draws the nonce from
  the operating system.
- **The joint statement** (membership and payment) binds the kind byte
  `0xff`, which no `CredentialPublic` takes, and its own program id: no
  ingress admits it, and its proof authorizes nothing under auth or owner.

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
