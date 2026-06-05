# Anonymous Moderation: zk-promises

> Based on: *"zk-promises: Making Zero-Knowledge Objects Accept the
> Real World"* ([ePrint 2024/1260](https://eprint.iacr.org/2024/1260))

## The problem

In a private space, content is encrypted and members may be anonymous
(or pseudonymous). But spaces still need moderation — spam removal,
reputation systems, banning bad actors. How do you moderate when you
don't know who posted what?

Traditional approaches break down:
- **Remove anonymity for moderators** — defeats the privacy goal
- **No moderation** — spaces become unusable
- **Trusted moderator** — single point of trust, can be abused

## What zk-promises offers

zk-promises provides **anonymous actions with accountable consequences**.
A user can post content anonymously while provably maintaining a
reputation score, rate limit budget, and ban status — all without
revealing their identity.

### Key concepts

**zk-objects** — Each user holds a private state object (reputation score,
rate-limit counter, ban flag). They prove properties about this state
using zero-knowledge proofs without revealing the state itself.

**Callbacks** — When a moderator wants to penalize a post (reduce
reputation, issue a ban), they issue a *callback* against that post's
ticket. The callback is posted to a public bulletin board. The user
must process it before their next action — they can't ignore it.

**Bulletin board** — An append-only log where callbacks and object
commitments are posted. This is the only shared state. It can be a
centralized server (trusted for integrity, not privacy) or a
decentralized Merkle tree on-chain.

**Forward secrecy of identity** — The moderator never learns *which*
user they're penalizing. They just issue a callback against a ticket.
The user processes it privately.

## How it fits into the messaging protocol

zk-promises sits at the **authorization layer**, below the CRDT sync
but above the transport:

```
  Real-time edits (fast, no proofs)
         │
    Merkle-CRDT sync
         │
    MLS encryption
         │
    zk-promises authorization gate
         │
  "Am I allowed to post? Prove it."
```

### Integration model

**Not on the hot path.** ZK proof generation takes 300-900ms — too slow
for every keystroke. Instead:

1. **Session start** — user generates a proof that they're authorized
   (reputation OK, not banned, rate limit not exhausted). One-time cost.
2. **Editing** — CRDT operations flow through Merkle-CRDT normally, fast
   and lightweight. No proofs per edit.
3. **Moderation** — moderators issue callbacks via the bulletin board.
   Users process them next time they start a session or come online.
4. **Rate limiting** — checked per-session or per-batch, not per-operation.

### The bulletin board in Kunekt

The bulletin board can be implemented as:
- A **special moderation document** in the space (itself a CRDT,
  synced via Merkle-CRDT). Works in fully P2P settings.
- A **blockchain DA layer** entry. Provides stronger availability and
  ordering guarantees.
- A **dedicated relay** trusted for integrity but not confidentiality.

## Tradeoffs

| Property | Impact |
|---|---|
| Proof generation ~700ms | Acceptable for session-start, not per-edit |
| Groth16 trusted setup | Can be replaced with universal setup (PLONK, Marlin) |
| Arkworks dependency | Heavy, not `no_std` — this layer runs on capable devices |
| User must scan callbacks | Offline users accumulate unprocessed callbacks |
| Bulletin board availability | If bulletin board is down, new sessions can't start |

## Integration status

**Future work.** The current plan is:

1. **Phase 1** — Ship with Merkle-CRDT sync + MLS encryption. Moderation
   is explicit (admin removes members from MLS group).
2. **Phase 2** — Add zk-promises as optional `kunekt-anon` crate for
   spaces that want anonymous posting with moderation.
3. **Phase 3** — Evaluate newer ZK proof systems (Jolt, SP1) that may
   reduce client-side proving cost, especially in WASM.

## Further reading

- [zk-promises paper](https://eprint.iacr.org/2024/1260)
- [Reference implementation (Rust/Arkworks)](https://github.com/moshih/zk-promises)
- [Groth16](https://eprint.iacr.org/2016/260) — the proof system used
- [OpenMLS](https://github.com/openmls/openmls) — group encryption layer
  that complements zk-promises
