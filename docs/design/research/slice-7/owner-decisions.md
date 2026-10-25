# Slice 7 owner decisions

Taken before the plan (`slice-7-mobile.md`), 2026-10-25. Slice 6's
decisions 1–18 (`research/slice-6/owner-decisions.md`) still stand.

S1. **Scope** [decided]:
  - first, a **"simplify and scale" milestone**:
    - (a) a simplification pass on the anchoring and venue protocol
      (slice 6's pin D): registration, windows, anchor keys and rotation,
      hand-back and re-sign, migration ranges and `venue_bound`,
      equivocation evidence and resume. Its review findings grew every
      slice, so the state machine is hard to reason about;
    - (b) a **scale test**: many agents and many simulated users across
      more than one machine, so that the goal of millions of users per
      space is measured instead of extrapolated;
  - then **M4, the credential AIR**, and **M5, the device profile**;
  - **M6, the signature chips** (SHA-256 and SHA-512, the bignum chip, the
    P-256 and Ed25519 drivers), moves to a later slice.

S2. **The scale test's hardware** [decided]: local machines on the owner's
  LAN (the owner's desktop and the other machines the owner has), with a
  real network and uneven hardware. The test is scripted and portable
  across those machines.

S3. **M5's gate** [decided]: the general zkVM's auth statement under the
  device profile proves in **at most 1 s on the owner's Fairphone 6**, the
  gate device (Snapdragon 7s Gen 3: 4 Cortex-A720 at 2.4–2.5 GHz and 4
  Cortex-A520 at 1.8 GHz, 7.5 GB of RAM, Android 16), reached over adb on
  USB. The memory budget is the plan's to propose (at most 1 GiB
  recommended). The projection is about 1.0 s, with no margin, so the plan
  carries extra levers and a fallback order (word-level memory, the CPU
  split by opcode family, threads weighted by core class, blowup and
  queries).

S4. **Native only** [decided]: the device prover is a native Rust library,
  aarch64 Android first and iOS later. No Wasm or browser prover in this
  slice.

S5. **The phone side** [decided]: the Rust prover library and a small
  **Android demo app**. A real passkey PRF through Android's Credential
  Manager derives the device secret; the app proves authentication and a
  payment on the device and submits them to a local space's ingress. iOS
  comes later. The tooling on the development machine: the Android SDK
  (`/opt/android-sdk`, `~/Android/Sdk`), NDK 27.2, `cargo-ndk` and Java;
  no Gradle on the path (the wrapper fetches it).

## The gate device, measured (2026-10-25)

`phone-fairphone6-s5kit.txt`: slice 5's phone kit (`spike/s5-mobile`,
`ea539e9e`), the auth statement, 12,951 steps, one segment, the kit's
MOBILE configuration (`2:38:20`: log blowup 2, so blowup 4, 38 queries,
PoW 20; format 24's Blake2s channel, the 22-chip shape of the spike's base
`a6f6adbc`). Every proof byte-identical to the x86 proof, the built
shape's verified (the floor is unverifiable by construction), at 31 °C,
unthrottled, battery 51%:
- **as built:** 4 threads, median 6.2–6.5 s, 2.0 GiB; 8 threads 5.1 s;
  x86, 4 threads, 1.72 s;
- **the floor** (the proxy without the page boundary): 4 threads
  2.6–3.0 s (2.59 s pinned to the big cores), 0.9 GiB; 8 threads 2.2 s;
  x86 0.84 s.

The ARM factor is about 3.5× the x86 reference (3.3–3.6). A flagship should
run about 2× faster than this phone.

## The owner's answers to the plan's questions (2026-10-25)

On draft 2's open questions and `simplify.md` §7. Each [decided]; the
slice-6 decisions each reverses are named.

S6. **The demo's relying party:** a subdomain the owner controls, serving
  only `assetlinks.json` for the demo's package and its committed demo
  keystore.

S7. **The groundwork in parallel:** 7.0a at once; M5's masking of the
  segment chips (7.14) and M4's 7.7, 7.9 and 7.10 beside M3.9.

S8. **C6, one anchor rule:** a `no_std` venue core in `vos-anchor` that
  every venue calls and the kit vendors. Reverses nothing.

S9. **C1, no migration:** a space that changes venue re-founds. The
  Clerk's limit is accepted: counterparties share a venue for good.
  Reverses decision 8's migration ranges, `proving.md` §7's venue
  migration, `spaces-pallet.md` call 5 (errors 24 and 28, event 5) and
  vector G14.

S10. **C8, registration from the venue's next window:** the founder signs
  `(venue, space, controller)`; no `start_window`. Reverses slice 6's
  plan-3 fix (the signed start; vectors G1 and G18 in part).

S11. **C4, equivocation is fully terminal:** evidence ends the space at
  every venue for good, with no resume anywhere, the pallet's design
  included, and no governance revive. The space re-founds under a new
  `SpaceId`; its sovereign funds leave by a controller or governance call
  (`dispatch_as_sovereign` stays callable on an ended space); its members
  register their credential leaves again (their secrets survive: S25's
  stable handle); the Clerk's pairs reset; the venue keeps the ended
  space's record as a tombstone it never prunes. Reverses decision 7
  ("equivocation suspends, then resume") and decision 18 (resume with the
  disputed window dead); `proving.md` §7's equivocation text;
  `spaces-pallet.md` call 6, error 23, event 9, `set_status`'s
  re-suspension, vectors G5 (its resume half) and G19.

S12. **C7, rooted statements only at the venues** in this slice;
  `venue_bound` goes. Reverses decision 8's per-program `venue_bound` and
  decision 10's "a rootless statement's `Seen` entry never expires", until
  rootless statements return.

S13. **C2, the node key is a node's only anchor key:** a compromised key
  means replacing the node. Reverses decision 7's rotation ("the node
  signs with its newest key the venue lists"), step 6.14b and
  `spaces-pallet.md` §13 questions 2 and 12, vector G15 in part.

S14. **C3, no hand-back:** the close writes `S_w` in a replicated row;
  the leader signs from it alone. Reverses nothing.

S15. **C5, five outcomes on the node:** `Taken`, `NotYet`, `Never`,
  `Unlisted` (the leader hands off its leadership), `Stopped`. Reverses
  nothing.

S16. **C9, no re-cuts:** a read not closed in time fails `NotClosed`, the
  caller asks again. Reverses slice 6's 6.14 re-cut rule (the plan's, not
  a numbered decision).

S17. **C10, agents report only for windows a read waits on**, an issuer
  opting in to every window. Reverses `proving.md` §7's "`S_w` over every
  agent's root".

S18. **C11, a window no one reported is not anchored.** Reverses nothing.

S19. **The Kreivo teammate:** `spaces-pallet.md` v2 and the vectors are
  regenerated in 7.1, and the teammate is told now
  (`teammate-note.md`, for the owner to send).

S20. **S3's gate is decided after 7.0a** (its masked-cost proxy on today's
  AIR); the plan aims at 1 s until then. Open until 7.0a.

S21. **The gate's statement:** the auth statement over the credential
  actor's Poseidon2 tree through the chip; the BLAKE2b one measured beside
  it.

S22. **A public payer:** pay is a proof of knowing `s` behind the row's
  owner digest, bound to the call and checked against the live row.

S23. **The Poseidon2 chip and M5's levers go into the device format and
  the node's segment format:** a second re-pin at the slice's end, once
  M5's levers settle (the agent image, the kernels, the verifier blobs).
  Reverses draft 2's "device format only" (the review's M1).

S24. **A device proof at ingress authorizes what an auth credential
  does.**

S25. **A stable PRF handle:** 32 bytes the founder draws once, kept
  across re-foundings, so members' device secrets survive one.

S26. **The scale targets T1–T6 as proposed**, adjusted after run 2.

S27. **The phone's memory:** at most 1 GiB peak resident, a target of
  768 MiB.

S28. **Threads:** the library's automatic choice; the four big cores
  recorded beside it.

S29. **The credential format's parameters by 7.12's grind:** blowup 4,
  47 queries, PoW 16 if the grind's 95th percentile on the phone passes
  50 ms; else blowup 4, 43 queries, PoW 20. Open until 7.12.

S30. **Item 68:** a `closes` row that does not decode is quarantined
  (moved aside, with an alert), the batch going on.

S31. **Slice 6's six owner's-call quality items** (1, 5, 34, 46, 54, 58)
  are folded in 7.23.

## On Fable's review of draft 3 (2026-10-25)

`plan3-fable.md`, "ready after fixes". Two new decisions, and three
amendments the owner took as the review proposed.

S32. **S23's leaf count, with its exit:** on 7.18's first day the node's
  kernel leaves are counted over the CPU split's proposed layout and the
  Poseidon2 chip. If any leaf would pass its `p2` budget (2^16 rows at 40
  queries) with the split, the split stays device-only and the node's
  format 41 takes the Poseidon2 chip alone, or nothing if that too
  overflows, at 7.21. **No fold-shape change in this slice** (no `p2` at
  2^17, no successor to format 32, `H_FOLD` unchanged). Narrows S23.

S33. **The phone:** the Fairphone 6 is the only device. Its sessions are
  batched, their number and timing planned (nine, P1–P9 in the plan's
  "How every step runs"), each asked for a week in advance with its list.
  Between sessions, iteration uses x86 timings scaled by the ARM factor
  and qemu-aarch64 for byte-identity and verification; neither proxy is
  a gate.

Amendments:
- **S7:** slice 6's re-pin batch is split: 7.8a (the pvm-internal items,
  right after 7.0, before 7.14 touches a chip) and 7.8b (the agent-side
  items and `blobs.lock`, after 7.3 and 7.11).
- **S11:** the divergence guard is part of it: the leader signs only an
  applied `anchor(w)`; before sending an anchor that would be evidence it
  asks its followers for theirs and sends nothing if any differs (an
  apply bug or a clone, alerted); a restored backup or a cloned store
  counts as a compromised node key in `docs/operations.md`. Also: the
  registration deposit is released on `Ended`.
- **S25:** pin I's scope carries the `SpaceId`
  (`scope = P2(TAG_SCOPE ‖ H(space ‖ agent ‖ instance ‖ name))`), so a
  shared handle never shares nullifiers; `SECURITY.md` states that two
  spaces sharing a handle can link their members' `member` and `owner`
  digests, and the app shows and pins the handle at first enrollment; the
  re-founding runbook re-seeds the new credential actor's tree from the
  ended space's `member` digests, with no member action. Also: `member`
  carries no epoch (`member = P2(TAG_MEMBER ‖ s)`).

## On Fable's review of 7.2 (2026-10-25)

`7.2-fable.md`, "fix, then merge"; its M1 asked the owner whether a
quorum overrides a dissenting minority in the divergence guard.

S34. **The divergence guard: the majority decides.** When a quorum of the
  representative's replicas (this one among them) holds the leader's row
  of a window at which the venue holds another root, the leader sends its
  anchor as the evidence even when a minority answers another row; each
  dissenting replica is alerted by name with the root it holds. A
  dissenter whose root equals the venue's held root names the
  equivocator (a fork of this representative); one equal to neither is a
  bug or a compromise. Without a quorum (too few answers, or a split with
  no majority) the leader sends nothing and settles nothing: it asks
  again every 2 s, its alert raised once. A dissent never settles the
  window for the leadership. Narrows S11's amendment ("sends nothing if
  any differs").

## On the scale runs' hardware (2026-10-26)

S35. **One machine besides the desktop.** The owner has one other machine,
  `compumax`, on the LAN. The scale runs put **3 nodes on compumax**, each
  in its own unit with its own memory cap and data directory; the drivers
  and the coordinator run on the desktop and reach the nodes over the real
  LAN. T1, T3, T4 and T6 are measured as the plan specifies. T2's knee on
  four node hosts or more, and run 2's rerun without the slowest host,
  are recorded as not measurable on this hardware, to be run when more
  machines exist. Narrows S2.
