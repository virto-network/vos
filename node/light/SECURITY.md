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
  merge handler writes.
- **What a device does not run, it keeps:** a peer's operation this
  device cannot run yet (a kind its build does not know, a later release
  of the actor than it installed, a run that faults here) is held and
  replayed by an install; one that is invalid (a frame no device records,
  a run that fails where its issuing device's was done) is quarantined,
  never applied, and listed with its author for the chrome (§8, C1). So
  no node stops the scope's sync, and garbage that opens correctly writes
  nothing. Excising what a device wrote validly before it was found out is
  later work: the remedy is removing the device.
- **Reads filter, never unapply:** an author that equivocated, and one
  the device set removed (cut off one past its node at its frontier, as
  the sealed read finds it), are filtered when a merge field is read,
  from their cutoff on; their rows stay. A removed author's operations
  that arrive after its removal is known are quarantined, so they never
  replace its earlier entries; an equivocation's forks both apply, so
  devices meeting them in either order read alike. A field keeps one
  entry an element and author, its latest: an applied write past a
  cutoff (a removed author's that arrives before the removal is known,
  which agent-mediated sync refuses past the frontier, or a fork's) still
  hides its author's earlier write to that element, which reads then fall
  back from to the other authors'.
- **A full disk refuses, never tears:** below a reserve of free room
  (64 MiB by default) an install, a call, an ingest and a replay are
  refused with nothing written, and succeed once room is freed; a cutoff,
  a push's queue and the device group's writes are exempt. A disk that
  fills anyway fails fjall's write, which then refuses every write until
  the store is opened again.

## The device group

- **Its secrets are in the store, in the clear:** the MLS group state
  (the leaf's signing key, the epoch's secrets), a held own commit (the
  next epoch's secrets), key packages' private keys, and the key archive
  (the naming secret and every confirmed epoch's scope keys), all in the
  store's `group` keyspace. The client wraps the directory under a key
  usable after the first unlock and keeps it out of backups
  (`light-node.md` §3.5, §8 A11); whoever reads the store reads every
  scope's data, past and present (no forward secrecy for history, by
  design).
- **It holds no admin key and no sync key:** commits and votes are signed
  by the client, the admin key behind the owner's prompt, the sync key
  after first unlock; the library gives the messages to sign.
- **It trusts no operation the log shows without its signature:** a
  candidate is processed only once its evidence verifies against the
  committer's admin key as this device knows it, each removal it carries
  a matured operation whose evidence verifies; each vote is verified
  against the voter's sync key and the candidate's place in this device's
  log; a log that does not chain stops the reading. A candidate is
  processed on a copy and swapped in only on confirmation, by this
  device's own count of the votes, never the agent's verdict.
- **A maturity is honoured only behind verified evidence:** each device-set
  call (operation, veto, second signature, resolution) is checked against
  its signer's key (a device's admin key, or the kit entry's), what that
  signer may sign and the delay it must wait; the log's word that an
  operation matured is honoured only once the evidence supports it: the
  operation's own, and either its delay passed with no verified veto of a
  device with a voice, no rival removal and, for a restore, no `alive`
  since (unsigned, the agent's word), or a verified second signature, or
  verified resolutions naming it (the kit's, or the latest of each of two
  seasoned devices with strong admins). A maturity asserted at a time
  past its entry's is refused, and an entry whose batch time goes back
  stops the reading; a removal freezes its target's probation as the
  agent does. Evidence
  posted after the maturity is waited for until the confirm window has
  passed; a maturity it never supports raises `Unsigned` and moves
  nothing. A device whose candidate removes a device on a maturity this
  device does not honour is refused.
- **The agent's policy is the log's:** operators set the delays, the
  seasoning, the probation and the confirm window through `Configured`,
  which every device takes as it reads it. The window bounds how long a
  candidate waits for its set and how long a device waits for evidence a
  maturity needs; a home that shortens it shortens both, and one that
  lengthens it holds a void candidate's keys in place longer. A device
  checks operations against the delays the log configured, not against
  its own: `Configured` is the operators' word, unsigned, so a home that
  sets a delay to zero makes every removal (and a leaked kit's restore)
  immediate on every device, and no device alarms on it.
- **A restore's device trusts the agent for what came before:** it starts
  its group from what it reads of the agent after its restore matured
  (the log's head, the device set, the kit), with no earlier view to
  check them against; from then it checks the log as any device does.
- **A device that cannot follow** reads on for the device set's
  operations, so its own regroup matures in its view, but takes no other
  candidate: it follows the others' epochs and the removals they carried
  by the agent's word (which moves no key), and its regroup's new group
  names only the devices it knew. A regrouper whose removal matures
  before its new group frees the others to commit.
- **Data keys come from the confirmed epoch alone**, and scope ids from
  the archive's naming secret, which is the store's from its first scope
  on: a store that named a scope does not join another group. A restored
  store keeps the recovered group's naming secret beside its own: its old
  scopes keep their ids, new ones are named by its own, so a leaked old
  naming secret unmasks no scope made after the restore.
- **A replaced admin key** signs from its replacement's verified maturity;
  a call its new key signs while that maturity's evidence is still to come
  waits for it, and falls if it never verifies. The device's next commit
  renews its leaf's credential to the new key, which every other device
  accepts only for that device and that key.

## The recovery kit and `R`

- **The kit's 32 bytes** (a phrase's, or a security key's `hmac-secret`
  over a fixed salt) give its ed25519 signing key and its X25519 sealing
  key. `KitSecret` is zeroized on drop, with no `Clone` and no `Debug`; a
  phrase's words are returned once, zeroized on drop, for the app to show
  (never as a QR). The security key's output crosses the app's process as
  YubiKit's answer, as a member secret's does.
- **`R = R1 ⊕ R2`:** `R1` sealed to each kit entry's X25519 key (an
  ephemeral agreement, XChaCha20-Poly1305, the agent's identity bound),
  `R2` at the agent, released only to a matured restore's device. The kit
  alone opens `R1`; the operators alone hold `R2`; together they read
  every key the recovery scope holds (§8 D3).
- **`R` rotates at every removal:** the device that commits a matured
  removal draws a new `R`, seals its `R1` to each of the kit's keys (no
  kit holder needed) and hands its `R2` to the agent in the commit's
  evidence; the agent takes it at the commit's confirmation and re-points
  the kit's reading of the recovery scope after it; the committer then
  seals the whole archive under the new `R`. A removed device holds only
  the `R` before, so with the operators it reads nothing pushed to the
  recovery scope after its removal. A kit rotation and a restore draw a
  new `R` too.
- **A drawn `R` is held aside** until the log makes it the kit's (the
  commit's verdict, the rotation's or restore's verified maturity), and
  never travels before. The other devices take it only from an archive
  sealed under an epoch's archive key whose `R` hashes to the one the
  admin call named, so no device can give the others another `R`; a
  device pushes nothing to the recovery scope while the log names an `R`
  it does not hold; and while a removal it honours is owed (matured, its
  commit not yet confirmed) it lets no `R` travel at all, neither in its
  archive nor under it in the recovery scope, since the removed device is
  still in that epoch. So an `R` a rotation makes the kit's in that window
  reaches no removed device either.
- **The kit's sealing keys are a device's own:** the claim's are the
  claiming device's, a rotation's or a restore's those its verified admin
  call carried; a commit re-seals `R1` only to those, never to keys the
  agent serves.

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

## The tree, and what reading it shows

- **The tree is kept whole from the credential actor's feed**
  (`TreeKeeper`): every write of the tree, read in order a page at a
  time, the member's path computed on the device. A feed query names the
  keeper's place in the feed, nothing of the member's, and is signed by a
  key drawn for it alone; the client sends it on the space's feed
  connection, which carries reads alone. So no node or gateway learns
  which leaf is the member's, and every proof is against the newest root
  the device has read.
- **Each page is checked against the root its last change names,** the
  one root a proof uses, which binds every leaf: a page that leaves
  another root, holds a leaf that is no digest, a change out of order or
  older than the last, or does not start at the keeper's place, is
  refused whole and the tree kept as it was. The feed is still the gateway's word: one that withholds changes
  makes the device prove against an old root, which ingress answers
  `RootStale` or `RootUnknown`.
- **The feed is read on a jittered timer of its own** (30 s, between
  15 s and 45 s), never because a proof is about to be made: the feed's
  connection is one circuit for as long as it is open, and a read just
  before each proof would join the proofs through it. A `RootUnknown` or
  `RootStale` answer makes the feed due within 10 s, at a time drawn for
  it: that read still precedes the retried proof, and since the feed's
  connection is one circuit while it stays open, two refused proofs each
  followed by a read on it link the two proofs' scopes to one device. It
  happens only when the ring no longer holds the device's root.
- **What a gateway can make the device hold is bounded:** a page at most
  48 KiB (or one change of at most 256 leaves), no slot past the lowest
  never used, as the actor places members, so about two nodes a leaf;
  and one read at most 256 pages. No path is given until a read reaches
  the feed's end.
- **A feed query names the keeper's place:** a restored keeper's first
  read names the place it last read from, which can link the new circuit
  to the last when few devices read the feed; a new device reads from the
  start soon after its claim.
- **Kept on the device:** the tree's leaves, which every member reads
  alike, and the feed's place; nothing in them is the member's but which
  leaf the keeper computes paths for, which is not kept.

## Proofs and the node's checks

- **`verify`** runs ingress's checks that need neither a clock nor
  state; the expiry window, the root's freshness and replay are the
  node's.

## The client over Tor

What `vos_light::tor` (the `tor` feature) keeps apart, and what it does
not (`light-node.md` §6.2–§6.7).

- **The route is decided before a byte leaves** (`vos_light::route`):
  every space is reached through its pinned onions unless the user opted
  its key-signed calls out of Tor, after `OPT_OUT_WARNING`, where the
  space offers a clearnet port and is not onion-only. Anonymous requests
  (proven calls, the tree's feed, the node's time, the onion set's
  refresh) and the personal agent's and `Homes`' traffic have no clearnet
  route at all: with no onion pinned they are refused, nothing dialed. A
  proven call goes only under its own purpose, which carries nothing
  else, so it never rides a connection that may be on the clearnet.
- **One connection a purpose, each its own circuit and SSH key:** each
  connection's stream takes an arti isolation token drawn for it alone,
  which arti's circuit manager shares with no other stream, and its SSH
  session authenticates with an ed25519 key drawn for it alone (its seed
  zeroized once the key is made), so the gateway cannot join two
  purposes, two spaces, or two proven calls by circuit or by key. A
  proven call and a fetch each take a connection of their own, closed
  once answered; the member's calls in a space, the feed, the personal
  agent and its background schedule each keep one while used. The
  anonymous purposes carry reads alone, so no key-signed call joins
  their circuits. A change of a space's routes closes every connection
  made under the old ones, requests in flight included. **Not hidden:**
  what a purpose's requests themselves carry (a member's signed calls
  name its key; a personal agent's calls its sync key), the timing of
  requests, and that one Tor client made them all to the same onion at
  once, which the gateway may correlate by time alone. **Its cost:**
  arti keys an onion's descriptor and introduction state by isolation,
  so each connection fetches the descriptor anew and a retry does not
  learn which introduction point failed; arti keeps each such record 48
  hours.
- **The gateway is pinned twice:** its onion address authenticates the
  service, and its SSH host key, pinned beside it, is checked at each
  handshake; a gateway presenting another key is not spoken to.
- **The onion set's refresh is the gateway's word:** a usable set (one to
  sixteen onions, each once) read from the registrar through the pinned
  set replaces it, as unsigned as any answer the gateway relays
  (`light-node.md` §8, H5). A gateway could steer a device to onions it
  controls; the SSH host keys come with the same answer.
- **arti's state is the app's:** arti's state and directory cache in the
  app's private directory, made private if missing; arti checks its
  permissions and refuses a directory others may write, and
  `ARTI_FS_DISABLE_PERMISSION_CHECKS` is ignored. The state holds guard
  choices and the directory, no key of the member's; it is kept out of
  the operating system's backup with the store.
- **Dormant sends nothing:** going dormant closes every connection (a
  request in flight ends unanswered), the spare and the screens, stops
  the idle timer, and refuses every request until woken.
- **Plain bridges only:** a pasted line naming a pluggable transport is
  refused, so a network that blocks Tor by inspection blocks the
  anonymous calls and the personal space, which wait (§8, H2).
