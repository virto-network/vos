# The work-result contract (RefinePayload v3)

Status: DESIGN (frozen wire proposal, adversarially reviewed 2026-07-08 —
3 verification lenses over vos, jar, and graypaper main; all findings
folded in). Implementation is vos-core-execution.md §4 steps A7–A9;
companion: `jam-entry-points.md` for how the accumulate entry that consumes
this reaches execution. Assumes the A0–A6 bug-fix arc has landed
(discard-on-panic, commit-then-outbox, blake2b blob addressing).

## 1. What this contract is

One byte-defined semantic for "what a refine produced", applied identically
by every consumer:

1. the **VOS host drain** (the native end-of-tick journal application —
   after this change an *optimization of* the defined semantic, not the
   only truth),
2. the **child-invoke conversion** (the host turning a nested child's
   work-result into the parent-facing invoke envelope — §4b; this is a
   real fourth applier site, not a footnote),
3. the **guest accumulate** (the thin APPLY that runs in-PVM on a JAM
   host, entered at instruction counter 5 — see `jam-entry-points.md`),
4. any **prover/verifier** (the transition digest binds the state
   transition into the io-hash public bytes — §5).

It replaces RefinePayload v2 (`vos/src/refine_payload.rs`), whose semantics
forked: the VOS host persists `payload.state` on every dispatch while the
guest replay path persisted it only on yield — a conformant JAM host would
silently lose every non-yielding state mutation.

## 2. Wire layout (version 3)

```text
[version: u8 = 0x03]
[flags: u8]              // bit 0 = continue_next, bit 1 = forbidden
[anchor_kind: u8]        // see §3
[anchor: 32 bytes]       // zero-filled when anchor_kind = 0x00
[reply_len: u32 LE][reply_bytes]
[effects_count: u16 LE]
  for each effect:       // per-effect encoding unchanged from v2
    [tag: u8][payload_len: u32 LE][payload_bytes]
```

Differences from v2, and why:

- **The `state` field is gone.** Post-dispatch actor state travels as an
  ordinary `Effect::Write { key: STATE_KEY, value }`, emitted by the guest
  framework as the **final** effect when (and only when) the state bytes
  changed. This kills the host/guest persistence divergence at the root:
  there is no host special-case to disagree with (deletes the push at
  `runtime.rs:801-815`), and a JAM accumulate applying the effects list is
  automatically state-correct.
- **Effect ordering**: effects apply in **wire order**; duplicate keys are
  legal and later wins per key. (The guest emitter batches by category —
  Writes, then Transfers, Provides, News, `context.rs:712-727` — so wire
  order is category-batched; within Writes, emission order is preserved.
  The framework appends the state write last within the Write batch.)
- **Strict canonical decode (new, normative for v3)**: the v3 decoder
  rejects (a) any effect whose payload is not *exactly* consumed by its
  fields, and (b) any trailing bytes after the last effect. The inherited
  v2 decoder accepts both (`decode_effect` never checks cursor exhaustion;
  `decode` never checks `pos == len`) — v3 closes this so "the wire bytes"
  is well-defined for the digest (§5).
- **`anchor_kind` + `anchor` are new** (§3).
- `reply` stays a field, not an effect: it goes to the *caller*, not to
  storage. It is excluded from the transition digest and bound instead as
  the io-hash return half — normatively, see §5.
- `continue_next`/`forbidden` flags carry over unchanged (the
  STATUS_FORBIDDEN envelope path is unaffected). `continue_next` remains
  scheduling metadata — the suspended task itself is data (TaskRecord /
  serialized state), never execution state.
- No delete effect exists on the wire (Write always carries a value);
  tag `0x05` is **reserved** for a future delete, not emitted.

## 3. The anchor

The anchor commits to **the state this refine ran against**. It is the slot
JAM's stale-work reconciliation needs (two work packages refined against
the same state), the fail-safe VOS's serialized path gets for free, and one
of the two independent binding points proofs use (§5).

| `anchor_kind` | meaning |
|---|---|
| `0x00` | **genesis** — refine observed no prior state; apply asserts `STATE_KEY` is absent **or empty** (ServiceStorage stores empty-value writes as present, `runtime.rs:340-342`; the A7 rework of `clear_continuation` removes the one source of empty `STATE_KEY` writes — see §4) |
| `0x01` | `anchor = blake2b-256(prior STATE_KEY blob bytes)` — apply asserts the current *effective* state (defined below) hashes to it |
| `0x02` | reserved: SMT state root (the succinct-witness generalization; the intended path for large state — not emitted yet) |

**Guest-side computation.** On a cold start the framework reads the prior
state and hashes those exact bytes (blake2b precompile) before
deserialization — none ⇒ kind `0x00`. The *channel* differs by path, the
computation doesn't:

- live/JAM path: the bytes come from `READ(STATE_KEY)`;
- witness-delivered path (B5, provable Tasks): the bytes come from the
  witness buffer — `READ` is zero-stubbed under tracing
  (`tracing.rs:376-393`), and the blake2b precompile is constrained
  in-circuit (Blake2bChip), so the anchor in public bytes is an in-circuit
  fact, not a claim.

On a warm restart (`ACTOR_HOLDER`) the framework carries the anchor
forward: after emitting a work-result whose final state was `S`, the held
anchor becomes `blake2b(S)`. Warm restarts are a live-path optimization
only — see §5 (provable Tasks are always cold).

**Effective state (normative).** The anchor is checked against the value of
the last `Write{STATE_KEY}` absorbed from previously **accepted**
work-results in the same apply scope, falling back to committed storage —
i.e. the journal-overlay view that `journaled_read` already implements
(`runtime.rs:290-295`, used by STORAGE_R at `:1066` for
read-your-own-writes). This matters because one VOS tick runs up to
`MAX_REFINE_ITERATIONS = 64` kernel re-entries (self-messages/yield loops),
each producing its own work-result, all absorbed into one journal that
reaches storage only at end of tick: **the tick's work-results form an
anchor chain** — iteration N's anchor is the hash of iteration N−1's final
state, verified against the overlay at absorption time, not against
end-of-tick storage. (Checking against raw storage would reject every
multi-iteration tick.)

**Apply-side check and failure.**

- **Mismatch ⇒ reject.** Nothing from the rejected work-result applies, its
  reply is dropped (caller retries), and the guest is **cold-restarted**
  (warm holder dropped) so its next dispatch re-reads durable state. This
  closes the warm-holder/failed-commit divergence window.
- **Mid-chain rejection**: rejecting iteration N discards N and everything
  after it (the un-drained suffix); iterations 1..N−1 stand. The
  continuation is cleared *directly* (host bookkeeping, §4), not via the
  discarded journal.
- On the serialized VOS agent thread a mismatch means a bug or a divergent
  replica; under future parallel refine (JAM in-core, concurrent Tasks) the
  same check is the stale-work detector. The reconciliation *policy*
  (reject-and-re-refine vs operand merge) stays an explicit open spike
  (vos-core-execution.md A17) — this contract only guarantees staleness is
  *detectable*.

## 4. Apply semantics (normative for all consumers)

Given a decoded (strictly canonical) v3 payload against effective state `S`:

1. Verify the anchor (§3). Fail ⇒ apply nothing, report rejection.
2. Apply `effects` in wire order:
   - `Write{key, value}` → storage write;
   - `Transfer{target, memo}` → append to the **deferred** outbound set —
     routed only after the durable commit succeeds (commit-then-outbox,
     A3);
   - `Provide{hash, data}` → preimage store;
   - `New{code_hash}` → service creation (id reservation per A6).
3. All-or-nothing with the dispatch: a rejected work-result or a failed
   durable commit applies zero effects and routes zero transfers.
4. `reply` goes to the caller only after (3) holds — the existing
   drop-reply-so-caller-retries contract, now actually safe.

**Host bookkeeping writes are not part of the work-result.** Continuation
header saves/clears are VOS-host-only writes, excluded from the digest, and
**must never target `STATE_KEY`**. Today `clear_continuation` pushes
`Write{STATE_KEY, []}` through the journal *after* the payload's effects
(`runtime.rs:1660-1667`) — under last-wins that would clobber the payload's
state write and break the next dispatch's anchor. A7 reworks it: the
continuation header is deleted directly; state teardown, if ever intended,
must be an explicit guest-emitted effect.

**Durable-node rule.** A dispatch whose payload carries no effects (pure
read) commits no durable node. A dispatch with effects but unchanged state
(e.g. only a Transfer) **must** produce a durable log node — the
state-unchanged skip in `commit.rs:806-808` drops these from history and is
corrected by A8/A13. (For synthesized **v2** payloads this rule is
evaluated by value comparison — see §8 — since v2 guests emit their full
state unconditionally.)

### 4b. Child-invoke conversion (the fourth applier)

The nested child INVOKE path is a `payload.state` consumer the v2 code
serves at `runtime.rs:1571-1587` (envelope `[status][state_len][state]
[reply]`, parsed by `lifecycle::invoke_raw`; the scheduler pattern persists
that state as its TaskRecord). Under v3:

1. The host extracts the child payload's final `Write{STATE_KEY}` for the
   envelope's state field and **strips it from the effects before**
   `absorb_effects` — child state travels to the *parent*, never to a
   child storage row. (v2's absorb currently writes nothing to the child
   row for state because state was a field; naively absorbing v3's state
   write would create child rows the Tasks model forbids and resurrect
   ghost state on later empty-state invokes.)
2. When the child emitted **no** state write (state unchanged), the host
   echoes the invoke *input's* state bytes (held at `runtime.rs:1484-1487`)
   into the envelope — parents always see the authoritative full state, so
   scheduler-style TaskRecords are never silently emptied.
3. The child's anchor is `blake2b(delivered state bytes)` (genesis when the
   parent delivered none), checked by the host against exactly what it
   wrote to the child slot before the run (`runtime.rs:1490`).

## 5. The proving seam

```
transition_digest = blake2b-256(
    b"vos/transition/v1"
    || version || anchor_kind || anchor || effects_count || effect_bytes)
```

- Domain-separated per the codebase convention (`zk.rs:80-96`); the
  preimage is a *splice* of the wire bytes (skips flags and reply), which
  strict canonical decode (§2) makes unambiguous.
- **Soundness direction, stated explicitly**: byte-different but
  semantically-equal encodings yield different digests *by design*; this
  is safe because every consumer applies exactly the bytes it digests —
  digest-equal ⇒ byte-equal ⇒ decode-equal ⇒ apply-equal. The adversarial
  direction requires a blake2b collision.
- **Folded public layout (frozen with this wire)** for provable Tasks:

  ```
  public' = anchor_kind (1) || anchor (32) || transition_digest (32)
            || app_public_bytes
  ```

  Fixed-width prefix ⇒ injective. Verifiers reconstruct `public'`
  identically before the io-hash equality check.
- **The framework composes the io-hash at halt** — not the handler. The
  current `bind_io` stashes a *finished* hash during handler execution, but
  the digest only exists at pack time; A7/B2 therefore change the stash to
  carry the handler's raw `app_public_bytes`, and the halt path computes
  `io_hash(public', return)` itself. Handler-supplied finished hashes are
  disallowed for provable Tasks.
- **`return` = the payload's exact reply bytes, normatively.** Today the
  return half is handler-discretionary with an empty/empty fallback
  (`run.rs:565-566`) — mere convention. For provable Tasks the generated
  halt path binds the v3 reply bytes as the return half; that is what
  makes excluding `reply` from the digest lossless.
- **Two independent anchors, both required.** The state anchor (`0x01`) and
  the entering-memory-image root (B1's `expected_initial_root`) do
  different jobs and neither subsumes the other:
  - the *state anchor* is checkable by apply-side consumers holding only
    the committed `STATE_KEY` blob — no memory image needed;
  - the *image root* binds the whole machine image (code placement, msg
    bytes, untouched `.bss`/`.data`) and is what stops a from-scratch
    prover doctoring non-witness memory while honestly computing anchor
    and digest. It is per-invocation and computable only by a verifier
    holding the full witness bytes (pre-state + msg), reconstructing the
    patched image root from the catalog-pinned *unpatched* image.
  The §5 binding is sound only when composed with the image-root check;
  a verifier that skips it learns "the pinned code produced these effects
  from the anchored state *or from a doctored image*".
- **Provable Tasks are always cold** witness-delivered invocations (B5/A9
  Tasks cold-start by construction). Warm restarts are a live-path
  optimization outside proving scope; the §3 anchor-carry paragraph is the
  live path of the same computation.
- **Proving ceilings** (documented so state-heavy Tasks don't silently
  become unprovable): provable `state ‖ msg` is bounded by the Task's
  declared witness buffer (16 KiB in the only in-tree example), *not* by
  A5's 1 MiB halt cap; the trace is bounded by `TRACE_GAS` (100M steps);
  the contract adds two blake2b passes over the state per proof (anchor on
  entry + the state write inside the digest). Large state belongs to
  `anchor_kind 0x02` (SMT root + touched-leaf witness), not to a bigger
  buffer.

## 6. Operand wrapping (the JAM seam)

Unchanged layout, now actually used: the encoded v3 payload is the
`WorkResult::Ok(data)` inside `encode_operand` (`vos/src/operand.rs` —
byte-identical to jar's `grey-state::encode_operand` fixed-LE variant;
note this is **jar's** operand encoding, not graypaper's compact-natural
§C.5 encoding — convergence of that layer rides with jar's own GP
alignment), item-wrapped with `ITEM_TAG_OPERAND` for accumulate's FETCH;
deferred transfers ride as `ITEM_TAG_TRANSFER` items. Two corrections
travel with this change:

- `operand::payload_hash` becomes blake2b-256 (the XOR fold was a
  placeholder; A4 already removes `simple_hash` from blob addressing).
- `WorkDigest.accumulate_gas` becomes the real gas budget of the guest
  APPLY (`jam-entry-points.md`); the host drain ignores it.

Memos over 128 bytes and oversized items are VOS-only affordances —
flagged by the `.vos_meta` hostcall/ABI tier marker (A12), not silently
truncated.

## 7. `CommitStrategy` under v3 (sketch — A8 refines)

The durable unit widens from "the STATE_KEY blob" to "the agent's dispatch
delta":

```rust
pub struct AgentDelta<'a> {
    /// Ordered writes from the applied work-result (STATE_KEY included).
    /// No deletes: the wire has no delete effect (tag 0x05 reserved).
    /// Tasks have no rows of their own, so this stays small.
    pub writes: &'a [(&'a [u8], &'a [u8])],
    /// (kind, anchor) the delta was applied against. NORMATIVE, not just
    /// audit: replay divergence detection depends on it (§8).
    pub anchor: (u8, [u8; 32]),
    /// EffectLog node: inbound msg, depth-1 invoke replies, recorded
    /// oracles (NOW_MS...), caller identity bytes (A12).
    pub log: Option<LogNode<'a>>,
    /// Outbound transfers, routed by the caller ONLY on Ok.
    pub deferred: &'a [(u32 /* target */, &'a [u8] /* memo */)],
}

fn commit(&mut self, delta: AgentDelta<'_>) -> Result<CommitReceipt>;
```

(`&mut self` matches reality — every strategy mutates bookkeeping:
`last_state`, clock, `next_seq`.) One redb txn per dispatch; checkpoints
(A13) are additional snapshot nodes at a DAG frontier, not a different
commit path.

## 8. Compatibility and migration

- **Version negotiation**: the host dispatches on the leading version
  byte. `0x02` payloads (already-installed actor blobs) get legacy
  handling — the explicit `state` field is synthesized into a final
  `Write{STATE_KEY}` (order-equivalent to the current absorb-then-push,
  `runtime.rs:792` + `:809-815`), anchor checks are skipped, and the
  durable-node rule is evaluated by **value comparison** (v2 guests emit
  their full state on every halt, so "carries effects" would turn every
  pure read into a durable node). `0x03` is what the macro framework emits
  after A7; unknown versions are rejected (fail-loud).
- **Replay divergence detection**: the self-check against effective state
  passes *by construction* during replay (the guest anchors whatever the
  runtime just served it) and detects nothing. Divergence is detected by
  comparing each re-emitted work-result's anchor against the
  `(kind, anchor)` **recorded in the corresponding durable log node**
  (`AgentDelta.anchor`, §7) — early and precise, replacing the late
  "handler is non-deterministic" length heuristic.
- **Rollout order**: (1) host accepts v2+v3 (A7), (2) macro emits v3 (A7),
  (3) `AgentDelta` commit (A8), (4) code-hash Task invoke + witness ABI
  use the same payload unchanged (A9/B5), (5) guest APPLY consumes
  operands at the accumulate entry (A15, after the jar entry-point work —
  which also requires **re-pinning zk program commitments** for every
  provable actor rebuilt with the prologue transpiler; see
  `jam-entry-points.md` §4).

## 9. Non-goals

- Reconciliation policy for anchor mismatches under parallel refine
  (A17 spike; this contract only detects).
- SMT-rooted anchors (`anchor_kind 0x02`) — arrives with `vos::zk::state`
  (B6); the kind byte reserves the slot so the wire doesn't change.
- A delete effect (tag 0x05 reserved, not emitted).
- Balances/amounts on transfers (VOS is coinless off-chain; the operand
  layout already carries the JAM fields as zeros).
