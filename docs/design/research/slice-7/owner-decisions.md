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
