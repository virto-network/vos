# Slice 6 code-quality review (31b7938e..24bf0b5e, tip 24bf0b5e)

This is a read-only review: nothing was edited or committed. It covers the
slice's code only (Rust, the justfile and shell scripts), which is 489 files,
+60,341/−14,421 lines. `docs/design` and the progress logs are left out.
Soundness is not in scope; the Fable review covers it. Every line number is at
HEAD.

Each item gives its location, what is wrong, the concrete change, the expected
line delta, a tag and a verdict.

Tags:
- **BP**: behaviour-preserving. Host-side code, tests, or prover code whose
  output bytes do not change.
- **BP-pin**: behaviour-preserving, but the code is compiled into a pinned
  program, so the change moves a **program id** and needs a re-pin. This
  covers:
  - the agent image and the `WINDOW`/`BALANCE`/`PREDICATE` kernels:
    `agent/default`, `agent/wire`, `agent/sdk`, `agent/tree`, the pinned
    test actors;
  - `final-verify.elf` and the final verifier's Wasm blob: `final-verifier`
    and `recair-air`;
  - the JAM statements service blob: `statement/src/bin/guest` and
    `statement/service`.

  No in-repo test pins the hash of the final-verify or statement-service
  blob. Their code hashes are computed at deploy (`tools/jam-dev/src/venue.rs:93`),
  so a move there means a redeploy, not a failing test. The guest-linked
  crates also embed `#[track_caller]` panic locations, so even a comment edit
  that shifts line numbers can move a blob.
- **BP\***: behaviour-preserving, but it changes a committed generated file (the
  conformance JSON) or the seeded bytes no golden pins.
- **NOT-BP**: changes a wire or storage format, removes public API, or changes
  what a gate checks. These are the owner's call.

Verdicts:
- **FOLD**: cheap and BP. Do it in slice 6.
- **CARRY**: take it into slice 7.
- Every BP-pin item is CARRY-only unless it is trivial and lands with one
  re-pin batch (see "Fold order").

Spot-checked for this report:
- 20 code comments cite `slice-6-on-chain.md` or `research/slice-N/`. Step
  numbers (6.17, 6.18, 6.19, 6.21) and pin letters (A–F) appear in about 40 more.
- `RERUN_GAS = 1 << 32` is defined twice, independently (`node/checker/src/carriers/needles.rs:66`,
  `node/prover/src/masked.rs:31`).
- The state-prefix list `[[0x00u8], [0x01], [0x03]]` is copied 5 times.
- The reads harness's step comparison (`agent/testkit/tests/agent/reads.rs:206-213`)
  leaves out `run.committed`, which `agrees()` checks.
- The anchor signature check is copied in 4 crates.
- `MaskLayout::log_size` and `MASKED_WRAP_PINS` (recair) have no production
  users.
- `node/venue`'s `mock` feature has no `check-no-*` gate.
- `store/mod.rs:309-310` is a doc comment attached to the wrong function.
- Clean:
  - `seeded-masks`, `watch`, `test-formats`, `disclosing`, `faults` and
    `debug-internals` are gated and covered by their `check-no-*` recipes;
  - `format_masked_tests.rs` is `#[cfg(test)]`;
  - no new `#[ignore]`;
  - `agent/wire` keys already use `#[repr(u8)]` enums;
  - the store uses the `NodeRow` enum;
  - the production paths in venue, host and prover have no `unwrap`/`expect`,
    except two thread-spawn `expect`s and `leader/serve.rs:220`.

**Do not merge `agent/default` with `agent/testkit`.** Their refine
`closes`, `invocation` and `workflows` look duplicated, but
`agent/testkit/src/lib.rs:4-7` makes the testkit an independent reference
model. Sharing code would hollow out the differential test. Only pure
definitions may be shared (item 50). The same applies to `kreivo/calls.rs`
and `kreivo/mock/types.rs`: `calls.rs:5-6` checks the vectors of one
against the other.

## Sizes

Production files over 800 lines:

| Lines | File |
|---|---|
| 1178 | `node/venue/src/kreivo/mock/mod.rs` (behind `mock`) |
| 1076 | `pvm/compiler/src/derive.rs` (1027 production) |
| 987 | `agent/wire/src/keys.rs` |
| 929 | `node/venue/src/kreivo/venue.rs` |
| 869 | `pvm/proof/recair-air/src/masked.rs` (about 600 production) |
| 847 | `agent/default/src/refine/invocation.rs` |
| 844 | `agent/testkit/src/workflows.rs` |
| 842 | `pvm/proof/src/format.rs` |
| 828 | `node/venue/src/kreivo/conformance/mod.rs` |
| 813 | `pvm/proof/src/prove.rs` |
| 811 | `agent/testkit/src/invocation.rs` |

Test files over 800 lines:

| Lines | File |
|---|---|
| 1567 | `node/venue/src/kreivo/conformance/scenarios.rs` |
| 1399 | `agent/testkit/tests/agent/reads.rs` |
| 1105 | `recair/tests/circuit/masked_gates.rs` |
| 1040 | `recair/tests/recursion/masked.rs` |
| 1020 | `statement/service/tests/service.rs` |
| 875 | `pvm/proof/tests/kernel/fixtures.rs` |
| 853 | `pvm/proof/tests/kernel/window_kernel.rs` |
| 827 | `node/host/tests/cluster/anchor_keys.rs` |
| 821 | `node/prover/tests/worker.rs` |

Longest new or grown production functions:

| Lines | Function | Location |
|---|---|---|
| 302 | `operation` | `agent/testkit/src/invocation.rs:248-549` |
| 262 | `drive` | `tools/jam-dev/src/command/statements.rs:161-422` |
| 243 | `run` | `final-verifier/wasm/run/src/main.rs:290-532` |
| 238 | `prove_on` | `pvm/proof/src/prove.rs:576-813` |
| 223 | `prove_once` | `recair/src/masked/mod.rs:384-606` |
| 195 | `messages_impl` | `agent/sdk-macros/src/messages.rs:296-490` |
| 174 | `handler` | `agent/sdk-macros/src/messages.rs:121-294` |
| 171 | `spaces` | `node/venue/src/kreivo/mock/mod.rs:473-643` |
| 151 | `send_anchor` | `node/venue/src/kreivo/venue.rs:444-594` |
| 144 | `take` | `node/host/src/leader/mod.rs:291-434` |
| 144 | `run` | `node/host/src/leader/batch.rs:26-169` |
| 137 | `operation` | `agent/default/src/refine/invocation.rs:367-503` |
| 135 | `submit` | `node/prover/src/worker.rs:548-682` |
| 116 | `replay` | `final-verifier/src/masked.rs:335-450` |
| 111 | `revealed_functionals` | `recair/src/masked/rank.rs:47-157` |
| 111 | `Prologue::new` | `pvm/compiler/src/derive.rs:915-1025` |
| 108 | `refine` | `statement/service/src/refine.rs:86-193` |

The longest test functions:

| Lines | Function | Location |
|---|---|---|
| 397 | `generate` | `kernel/fixtures.rs:478-874` |
| 244 | `a_malformed_proof_is_an_error_never_a_panic` | `masked_gates.rs:617-860` |
| 210 | `no_carrier_that_leaves_the_prover_role_holds_its_internals` | `carriers/audit.rs:126-335` |
| 168 | `the_window_is_stated_at_the_model_venue` | `window_kernel.rs:686-853` |

---

## Cross-cutting

1. **Slice-plan narrative in code.** BP. FOLD for host crates, tests and the
   justfile. In guest-linked crates the edit rides the re-pin batch (see the
   BP-pin note above).
   - Step numbers:
     - `node/prover/src/lib.rs:1` "(`slice-6-on-chain.md`, 6.18)"
     - `pvm/proof/statement/service/src/lib.rs:1` "step 6.19"
     - `node/host/tests/chain/main.rs:1` "6.21"
     - `node/venue/src/kreivo/conformance/mutations.rs:1-3` "6.17", "spike 6c/6a"
     - `kreivo/mock/mod.rs:3` "6.17b"
     - `tools/jam-dev/src/live/statements.rs:24` "as measured at 6.19"
     - `pvm/proof/tests/kernel/throughput.rs:1` "(6.18)"
     - `justfile:83` "6.20" and `justfile:209` "6.21"
     - `node/host/benches/cuts.rs:7` "(slice 4)", and `:2,39` "the plan's gates"
   - Slice-doc paths:
     - `pvm/proof/anchor/src/lib.rs:1`
     - `final-verifier/src/lib.rs:2`
     - `recair/src/masked/mod.rs:2-4`
     - `masked/rank.rs:1`, `masked/rng.rs:1`
     - `recair-air/src/masked.rs:2`
     - `pvm/proof/src/format.rs`, `security.rs`
     - recair tests: `masked_gates.rs:1-2`, `leakage.rs`, `common/leakage.rs`
   - Pin letters that will rot when the slice doc is archived:
     - "pin D/F": `accumulate.rs:2,11,31,35`, `verdict.rs:41`, `refine.rs:13-14`,
       `statement/src/lib.rs:422`, `node/prover/src/lib.rs:21`
     - "pin A/B/C": `masked.rs:4`, and 24 times across recair/final-verifier
     - "§6.1–6.5" and "pin F's order" as the mock's method docs (`mock/mod.rs:664,824,913,988,1093`)
   - Spike and measurement labels:
     - `SPIKE_PATH_*` and "spike 6.0a" / "[measured, slice-6-progress.md]":
       `kernel/reads.rs:8,35,39,42-43,164`, `window_kernel.rs:60-64,226,651`,
       `cut.rs:44,52`
     - "Soundness 2/3/6/8/9, leakage 1": `masked_gates.rs:254,266,385,492,527,612`
   - People: "the Kreivo teammate's pallet": `kreivo/mod.rs:7-9`,
     `venue/src/lib.rs:18`, `conformance/mod.rs:396`
   - Forward-looking: `recair/src/wrap.rs:235-236` "until the venues take
     `format::MASKED_WRAP`" is stale, since venues already take only 39
     (`final-verifier/src/lib.rs:13-14`).
   - **Change:** cite stable spec sections instead: `proving.md` §5 (R1–R8),
     `spaces-pallet.md`, the statement design. Rename `SPIKE_*` → `BUDGET_*`.
     Also "no longer makes / writes" (`justfile:111,131`) → "does not".
   - The same wording also sits in the generated `ABOUT` strings
     (`mutations.rs:322`, `scenarios.rs:1563,1565`), which end up in the
     committed `mutations.json` and `spaces.json`. Fixing those is BP\*:
     regenerate with `just conformance`. CARRY, or FOLD with the
     regeneration.

2. **Left over from the mechanical rename of "format 39/28/32" to
   `format::MASKED_WRAP`/`format::WRAP`.** About 50 doc lines now run past the
   wrap width, and the two naming styles are mixed.
   - final-verifier: `masked.rs:1,85,102-128,470-499,542`, `constants.rs:16-24`,
     `layout.rs:1,76,379,473`, `lib.rs:381`, `unmasked.rs:1,86`.
   - recair: `wrap.rs:2,7,165,211,263`, `prove.rs:2-5` ("the wrap's (28)", and a
     doubled path), `tree.rs:239,309`, `fold/child.rs:2,8,20,90,358`,
     `masked/mod.rs:31,97,100` (a panic text says "format 39").
   - recair-air: `p2.rs:19-22`.
   - statement: `lib.rs:5,52,55,59` vs `:130` ("39, and 28"), `model.rs:298`.
   - `security.rs:187-188`: a broken wrap, "`[3, 3, 3,` / `2]`".
   - `bin/final-verify-test.rs:1`.
   - fuzz `golden.rs:1,12,116`.
   - `accumulate.rs:28`.
   - **Change:** rewrap and settle on one name per format. Keep
     `PREPROCESSED_ROOT_39`: it has 3 outside users, so renaming it is
     NOT-BP.
   - BP for recair, statement-host and fuzz: FOLD. For
     final-verifier, recair-air, the statement guest and the service it is
     BP-pin (panic locations): FOLD only if the blob hash comes out unchanged,
     otherwise ride the re-pin batch.

3. **Refusal and verdict codes written as magic numbers, though
   `vos_statement::Refusal::*.code()` exists and production uses it.** BP,
   ±0. FOLD.
   - `kreivo/venue.rs:670` `Refused(2)`, `:676` `Refused(3)`, `:778`
     `Event::Refused { code: 6 }`.
   - jam-dev `venue.rs:352` `Ok(0 | 6)`. It also recomputes `statement.id()`
     although `id` is in hand at :347.
   - `command/statements.rs:233` `code >> 8 != 1`, and `:392-394`.
   - `node/prover/src/worker.rs:617,620` and `node/venue/src/lib.rs:73`:
     `0x1000` three times. Name it `vos_venue::UNJUDGED_FROM` or
     `vos_venue::unjudged(code)`, and name the variants in the comments
     "5 goes again" (`worker.rs:618`) and "repeat (6)" (`:648`).
   - Tests:
     - `kernel/fixtures.rs` `generate`: about 20 `|code| code == 2..7` sites,
       plus `by_words` 0x108/0x109 (:596);
     - `balance.rs:163`, a second `by_words`;
     - `window_kernel.rs:752-850`, including `const WORDS: u32 = 0x108`;
     - `carriers/audit.rs:56` and `cluster/prover.rs:58` `Refused(6)`;
     - `kreivo/tests.rs:693`.

     Use one shared `by_words` in `common`.
   - Service codes: jam-dev `venue.rs:169-182,286-294` and
     `command/statements.rs:401,404` match `code if code == AnchorCode::X as u32`
     (11 arms). A `TryFrom<u32>` in `verdict.rs` would touch the service crate
     (BP-pin). FOLD instead a host-side `fn anchor_code(u32) -> Option<AnchorCode>`
     in jam-dev, and CARRY the trait impl.

4. **The anchor signature check and the root-freshness rule are each
   open-coded across crates.** BP. FOLD for the host side, CARRY for the guest
   side.
   - The `VerifyingKey::from_bytes(..).is_ok_and(verify_strict(digest))` check
     appears 4 times: `node/venue/src/lib.rs:453-459`, `kreivo/venue.rs:795-801`,
     `tools/jam-dev/src/venue.rs:323-329`, `node/host/src/leader/close.rs:92-98`.
     Add `pub fn vos_venue::signed(&Anchor, &VenueId) -> bool`. vos-anchor has
     no ed25519 dependency, and the mock's `verifies` (`mock/mod.rs:1133`)
     stays separate on purpose. About −18.
   - The `MaxRootAge` freshness test appears 8 times on the host:
     `venue/lib.rs:250-253,486`, `kreivo/venue.rs:481-482,720-724,845-846,890-894`,
     and jam-dev `venue.rs:154-157,375-379`. The `checked_add` form at :378
     differs only at u64 overflow. Add a `vos_venue::fresh(clock, w, now)`
     helper, about −15.
   - Also twice in the guest/service: `statement/src/model.rs:144-149` and
     `service/src/accumulate.rs:246-252`, plus `seen_expiry` at
     `statement/src/lib.rs:307-316` and `verdict.rs:57-68`. Add
     `WindowClock::root_expiry` in vos-anchor and `vos_statement::seen_expiry_of`.
     BP-pin, and vos-anchor is vendored into Kreivo's kit, so CARRY.
     `accumulate.rs:298-303` uses `saturating_sub` on purpose; leave it.

5. **Small helpers copied everywhere.** BP. FOLD for hex, CARRY for the lock
   helper.
   - Hand-written hex, although the `hex` crate is already a dependency:
     `checker/carriers/needles.rs:94-96`, `cli/tests/cli.rs:247`,
     `host/src/space.rs:388`, `chain/venues.rs:331-333`,
     `cluster/anchor_keys.rs:398`, `statement/tests/fixtures.rs:184`,
     `final-verifier/wasm/run/src/main.rs:343,384`.
   - The "lock, recover from poisoning" helper is written 12 times across
     venue, jam-dev, prover and checker. Sharing it across crates is worth
     little.

---

## pvm/proof/recair (prover-only)

recair moves no program id. The masked proof bytes are random, so no golden
pins them. The unmasked wraps are pinned by `just fixtures`, so re-run it after
items 6–9.

6. **`masked/mod.rs:384-606` `prove_once` is 223 lines.** BP. FOLD.
   - Extract at its seams:
     - `commit_main` (412-436)
     - `commit_interaction` (446-479)
     - set/prover build (481-502)
     - `commit_composition` (504-533)
     - `checked_points` (535-554)
     - out-of-domain check (558-575)
     - `rank_check` (577-597)
   - Thread `rng` and `channel` through, and **keep the `rng` draw order**:
     no golden seeded bytes exist to catch a reorder.
   - At 589-590, `MaskStats { attempts: 0, .. }` is a placeholder that the
     caller patches at :358. Return the R1 measurements and build `MaskStats`
     in the attempt loop.
   - About +15 for signatures, then roughly 0 net.

7. **Dead code and seams left by deleted paths.** BP, about −20. FOLD.
   - `masked/layout.rs:116-118` `MaskLayout::log_size()` has no caller. The
     test's `.log_size()` call is on `CircleCoefficients`.
   - `context/mod.rs:559-563`: `h8_gate(inputs, out: Option<Var>)` is only
     ever called with `None`, since `h8_into` was deleted. Fold it into `h8`.
   - `masked/mod.rs:97-101` `MASKED_WRAP_PINS` repeats
     `vos_pvm_final_verifier::masked::PINS`, which is tested equal to the
     registry (`final-verifier/src/masked.rs:596-609`). Its only users are
     `tests/circuit/masked.rs:21,167,169`. Delete it. The comment that
     cites it at `recair-air/src/masked.rs:64` is a guest-crate comment, so
     edit it with item 2.

8. **`pub` items that exist for tests.** BP. FOLD.
   - `pub use layout::MaskLayout` (`masked/mod.rs:78`) is used only by
     `tests/circuit/masked_prover.rs:156,205`. Move that test
     (`masked_prover.rs:149-206`) in-crate and make the type `pub(crate)`.
   - `pub use rank::rank_m31` (`mod.rs:79`) is used only by
     `masked_prover.rs:232`. Move the test in-crate, or gate the re-export
     behind `seeded-masks`.
   - `Circuit::check_reads` (`circuit.rs:264`) has no outside user; make it
     private.

9. **The masked preprocessed lifting and extension is written twice.**
   `prove::masked_preprocessed_root_on` (`prove.rs:181-206`) and
   `prove_masked_checked` (`masked/mod.rs:304-328`) both do: tallest +
   `MASKED_LOG_CONSTRAINT_EXPANSION` + blowup, twiddles, then `interpolate` →
   `extend`. prove.rs uses unchecked addition with `unwrap_or(0)` where
   mod.rs uses `checked_add`, and prove.rs:191 has a `use` inside the
   function.
   - **Change:** `pub(crate) fn masked::lifting_log_size(..) -> Option<u32>`
     and `extend_preprocessed(..)`.
   - BP: the `PREPROCESSED_ROOT_39` pin test (`kernel/constants.rs:73`) catches
     any drift. About −12. FOLD.

10. **`circuit.rs:311-402` `unread_lane_reads` is 92 lines.** BP, about −10.
    FOLD.
    - The census of absorbed, partial and computed wires (312-348) becomes
      `fn lane_census`.
    - "Slot w absorbs lane j" is tested twice (288, 321-323); add
      `P2Wiring::absorbed(w) -> [bool; 4]`.
    - `== BaseField::from(0)` at 72, 288 and 322 → `is_zero()`.

11. **Small idioms.** BP. FOLD.
    - `tree.rs:132-138`: `Built::encoding` turns a postcard error into empty
      bytes with `.unwrap_or_default()`, so the carrier audit would silently
      see nothing. Use `expect`; the method is under `watch` only.
    - `trace.rs:336`: `for row in 0..rows.len()` indexes `positions[row]`;
      use `iter().enumerate()`.
    - `compile/program.rs`:
      - `std::collections::BTreeMap` is written out in full at 221 and 230;
      - `power_rows` has an `.unwrap()` on `max()` at 240; use `chunk_by` on
        the sorted powers;
      - `reach` returns a three-`Vec` tuple (191); use a small struct;
      - `lower` is still 88 lines.

12. **The unmasked wrap prover ships in every build.** The final verifier links
    format 28 only under `test-formats`, but recair exposes `wrap::prove_unmasked`
    and `prove_unmasked_with` (`wrap.rs:237-252`), the Postcard arm of
    `proof_bytes`, and an ungated `postcard` dependency (`Cargo.toml:14`).
    - **Change:** add a recair `test-formats` feature that forwards to the
      final verifier's, and gate these behind it. The users are
      `pvm/proof/tests/common/mod.rs:544`, `kernel/fixtures.rs:472` and the
      recair tests.
    - NOT-BP (removes default-build API). CARRY.

13. **`masked/rng.rs:87-144` `witness_digest` lists the configuration words
    again.** `vos_pvm_proof::proof::statement_header_words` already produces
    them. BP\* (it changes the hedge input, so seeded bytes change; nothing
    pins them). CARRY.

14. **recair tests.** BP. FOLD unless marked.
    - Duplicated harness code:
      - `masked_prover.rs` `verify` (119-147) is a Blake2b-only copy of
        `masked_gates.rs` `public_sum`/`verify_as`/`verify` (82-114);
      - `prove` is in both files (`masked_prover.rs:91-106`, `masked_gates.rs:116-127`);
      - `masked_gates.rs` `prove_set` (133-191) re-implements
        `prove::prove_masked_on`;
      - the `sources` file walker is at `gates/pins.rs:13` and
        `circuit/masked.rs:236`;
      - `bump(&mut BaseField)` is at `recursion/masked.rs:208` and
        `circuit/modes.rs:209`.

      About −60.
    - `recursion/masked.rs` (1040 lines): move `mod heavy` (705-1040) into its
      own file.
    - CARRY: split `masked_gates.rs` (1105 lines) into soundness (254-611),
      malformed (612-864), freshness (865-932) and shape/lengths (933-1105).
      Turn the 244-line case table in
      `a_malformed_proof_is_an_error_never_a_panic` into
      `fn malformations() -> Vec<(String, Mutation)>` plus a short loop.

## pvm/proof/recair-air, pvm/proof/final-verifier

These are guest code: `final-verify.elf` and the Wasm blob.

15. **`final-verifier/wasm/run/src/main.rs:290-532` `run` is 243 lines.** It
    is a host tool, so BP, about −50. FOLD.
    - The sequence "instantiate, get the typed function, write the input,
      call" appears 5 times (314-327, 389-394, 463-472, 484-488, 522-525).
    - The perf-counter builder appears twice (317-322, 450-456).
    - Semantics are parsed at 294-298 and printed again at 506-510.
    - A stray `use wasmtime::AsContextMut` sits at :221.
    - **Change:** a `Runner { engine, module, linker, semantics }` with
      `call(export, input)`; `judge()`, `anchors()`, `statements()` and
      `bench()` arms; `FromStr` and `as_str` on `Semantics`.

16. **`unmasked.rs` duplicates the masked shape helpers.**
    - `check_samples` (197-207) repeats `masked::samples_fit` (247-259).
    - `check_shape` (158-175) uses four `if`s where the masked side compares
      one array (274-284).
    - Make `samples_fit` `pub(crate)` and reuse it. Also make
      `masked::check_shape` (:268), which has no outside user, private.
    - The unmasked code is compiled only under `test-formats`, so the
      production blob is untouched. BP, about −12. FOLD.

17. **The three-component construction is written 3 times, the dummy layout 5
    times.**
    - Three components: `Components::new` (`recair-air/src/lib.rs:155-185`),
      `WrapComponents::build` (`masked.rs:471-518`), `WrapComponents::bind`
      (554-598). Add `fn evals(relation, log_sizes)`.
    - The dummy layout, `build(&GateRelation::dummy(), &BlindRelation::dummy(), sizes, &[zero; 3])`:
      `final-verifier/src/masked.rs:514-519,548-553`, `recair-air/src/masked.rs:616-623`,
      `masked_prover.rs:108-116`, `recursion/masked.rs:113-121`. Add
      `WrapComponents::layout(log_sizes)`.
    - About −45. BP-pin: the allocation order is kept, so the AIR and the
      proof bytes do not change, but the ELF does. CARRY.

18. **`final-verifier/src/masked.rs:335-450` `replay` is 116 lines, and "lift
    the components, then evaluate the composition" is written 4 times.**
    - Seams in `replay`: `admitted` (341-379), `check_composition` (424-444).
    - The 4 copies: `final-verifier/src/masked.rs:424-444`,
      `recair-air/src/masked.rs:657-665,817-826` (tests), `recair/src/masked/mod.rs:558-573`.
      One recair-air `eval_lifted_composition(..)` serves all of them.
    - About −25. BP-pin. CARRY.

19. **`recair-air/src/masked.rs` (869 lines) could split** into
    `masked/component.rs` (`Rebound`/`MaskedComponent`, 164-295) and
    `masked/wrap.rs` (`WrapComponents`, 461-599).
    - Also, the literal tree count `3` (`masked.rs:397,400`) and the final
      verifier's `masked::TREES = 4` are two hand-kept counts of one layout.
      Define them once in recair-air.
    - BP-pin. CARRY.

## pvm/proof/anchor, pvm/codec, pvm/proof/statement (+ service)

These are guest code: `final-verify.elf` and the statement-service blob.
vos-anchor is also vendored into Kreivo's verifier kit.

20. **Constant-byte groups where `#[repr(u8)]` enums belong (owner rule).** The
    wire bytes stay the same. BP-pin, ±0. CARRY (High; first in the slice-7
    re-pin batch).
    - `service/src/verdict.rs`: tags 0-5 are bare literals, written twice,
      in encode (113-173) and decode (184-253). **Their order does not match
      `item::Kind`**: Kind's 4 is `Control`, but the verdict's 4 is `Refused`
      and its 5 is `Control`. A private `enum Tag` makes this explicit.
    - `service/src/state.rs:51-57`: `pub const SPACE..QUEUED: u8` key prefixes.
      Use `enum Prefix`; the outside users (jam-dev `live/statements.rs:211,231,243`,
      `tests/service.rs:893,982`) only use `CURSOR`, `GAS`, `SEEN` and `QUEUED`.
    - `statement/src/bin/guest/mod.rs:45-54`: the modes
      `WORDS`/`JUDGE`/`ANCHORS: u8` and the verdicts `ACCEPT..UNDECODABLE: u64`.
      Use `enum Mode` and `#[repr(u64)] enum Verdict`.
      `statement/tests/support/jam.rs:94` hard-codes the mode byte `[2]`.
    - `service/src/item.rs:112-138`: the `Op` tags 0-3 are repeated in
      `encode_to` and `decode_from`.

21. **The codecs for flags, `Option<u64>`, program ids and pins are written 4
    times.**
    - `service/src/config.rs:105-122` repeats `vos_statement::decode_program`
      (`statement/src/lib.rs:254-266`), M31 bound included, and the 0/1 flag.
    - `model.rs:270-276` has its own `flag()`.
    - `state.rs:126-142` has `put_option`/`option`, and `:170-174` decodes
      the flag again.
    - `model.rs:50-77,192-193,221-222` and `config.rs:84-85` encode the pin.
    - **Change:** `Reader::flag`, `Reader::option_u64` and `codec::option` in
      `vos_anchor::codec`; a public `ProgramId::decode_from`; and
      `Pin::{encode_to, decode_from}`.
    - About −45. BP-pin (the bytes are identical). CARRY.

22. **The service's outcome codes are untyped.**
    - `accumulate.rs` has 26 `XCode::Y as u32` casts and `refine.rs` 6. The
      handlers `register`/`migrate`/`anchor`/`control` (`accumulate.rs:185,217,254,316`)
      return a bare `u32`. Return the code enums and convert once in `apply`
      (147-175).
    - `state.rs:249` `Outcome.kind: u8` with a `u8::MAX` sentinel → `Option<Kind>`.
    - About −15. BP-pin. CARRY.

23. **The service pulls another crate's binary source in by `#[path]`.**
    `service/src/bin/statement-service.rs:37` includes
    `../../../src/bin/guest/runtime.rs`. Its `heap-peak` feature exists only to
    keep the included `heap.rs` free of an unknown-cfg warning.
    - Duplicated between the two guests:
      - the `_start` trampoline (`guest/mod.rs:18-30` vs service bin `51-73`)
      - the host-call constants (`34-37` vs `95-103`)
      - `#[repr(C)] struct Output` (`124-128` vs `221-225`)
    - Change: move them into `runtime.rs` with an `entry!` macro (about −35),
      and later a `vos-pvm-guest-rt` crate, which also drops the dummy
      feature.
    - BP-pin. CARRY.

24. **Long guest functions.** BP-pin. CARRY.
    - `service/src/refine.rs:86-193` `refine` (108 lines): split into
      `refine_register`, `refine_migrate`, `refine_anchor` and `refine_control`.
      Also, `:255` hashes the id again although `admit` already computed it.
    - `statement/src/bin/guest/mod.rs:186-279` `verify` (94 lines): extract
      `vectors` (203-214) and `lookup_proof` (237-254). `Request::Words` and
      `Check::Words` duplicate each other, and `let words = out;` (168-173) is
      redundant.
    - Service bin: `fetch` (107-120) and `Proof::proof` (138-157) do the same
      read; add `fn fetch_exact`.

25. **Missing codec pieces in vos-anchor.**
    - `Anchor` and `Migrate` have no `decode_from` and no `Migrate::BYTES`, so
      the service takes N bytes and keeps its own `MIGRATE_BYTES`
      (`item.rs:251,255,268-269`).
    - `state.rs:67-89`: `keys::anchor` and `keys::evidence` are identical
      apart from the prefix.
    - `Evidence::decode` splits at a bare `64` (`:231`).
    - `RootKind` (`anchor/src/lib.rs:254-276`) has `from_u8`, `TryFrom` and
      `decode_from` with the same logic.
    - `pvm/codec/src/anchor.rs:51-89` decodes by hand-computed offsets. That
      keeps its `InvalidDiscriminator` detail, so this one is Low.
    - Additive. BP-pin, CARRY.

26. **Dead or write-only public API.**
    - `service/src/accumulate.rs:471-474` `pub fn kind(&Outcome)` has no
      caller anywhere. Deleting it should not change the blob, since the
      linker drops it; confirm the hash. FOLD.
    - `vos_anchor::SpaceGenesis::version`: `encode_to` always writes
      `GENESIS_VERSION`, whatever the field holds, and the repo has 0 readers
      across 11 constructors. Drop the field. NOT-BP (public API in the
      vendored kit). CARRY, or fold before the kit is tagged.

27. **The production `final-verify` serves a golden-vector mode.** `pvm-guest`
    enables `vos-anchor/vectors`, which adds the `ANCHORS` mode
    (`guest/mod.rs:203-214`). That mode is harness code. Move it to
    `final-verify-test`. NOT-BP (guest interface). CARRY.

28. **`service/src/lib.rs:92-107` `natural` and `accumulate.rs:73-94`
    `Operand::decode_input`** duplicate `vos_pvm_program::read_nat` and
    `vos_wire::jam::Operand`. The service accepts non-canonical naturals where
    `read_nat` refuses them. NOT-BP. CARRY.

29. **`statement/service/tests/service.rs` (1020 lines).**
    - Move the `Rig` harness (48-268) into `tests/service/rig.rs`. BP. FOLD.
    - The 95-line control test (748-842) can be split later. CARRY.

## pvm/proof (src), pvm/compiler, pvm/runtime, fuzz, kit

30. **`pvm/compiler/src/derive.rs`: the RISC-V encoder closures in
    `Prologue::new` (930-967) repeat `linker/differential.rs:185-215`,
    `linker/tests.rs:59` and `tests/derive_bounds.rs:23-37`.**
    - Move them into a `pub(crate) mod rv` of `const fn`s. `Prologue::new`
      then drops from 111 to about 55 lines. About −40.
    - BP: the kernel bytes are identical. Confirm with `derive_bounds` and the
      kernel program-id tests. FOLD.
    - The file split is CARRY: `derive/graph.rs` (377-703), `derive/kernel.rs`
      (704-906), `derive/prologue.rs` (908-1026).

31. **`pvm/proof/src/prove.rs:576-813` `prove_on` (238 lines).**
    - Seams: side notes (590-622), trace + `Sizes::Pinned` (632-653), commits
      (655-690), boundary mix + PoW (692-712), interaction (714-748), assembly
      (772-813). `ProveRequest`/`Sizes` (399-447) → `prove/request.rs`.
    - BP as long as the extraction is pure, but this is the prover's hot path
      and the proof bytes are pinned. CARRY.

32. **Small proof-crate items.** BP. FOLD.
    - `chips/memory_page.rs:656`: `if k < FIRST_WRITABLE { 1 } else { 2 }`
      repeats the `memory_layout::Permission` discriminants. Use them.
    - `chips/blake2b/columns.rs:1-12`: the module doc still mentions the
      removed "nibble AND witnesses" and does not describe
      `compression_columns!` or `BoundaryColumn`.

33. **`pvm/runtime/src/refine_host/jam.rs:26-46` `jam_gas::fetch`** matches
    bare kinds 0-15, while `mod fetch_kind` (67-80) in the same file names 0,
    3, 4, 5, 6 and 13. Use the names: BP, FOLD. A `FetchKind` enum is CARRY.

34. **Fuzz.**
    - `mutation.rs` `reshape` (124-143): the `Sampled`/`Queried` arms are
      duplicates; add `reshape_nested<T>`. BP, FOLD.
    - `examples/paths.rs:103-106` repeats `Golden::verify`; have `verify`
      return `Result`. BP, FOLD.
    - Splitting the `Mutation` enum into byte and structural mutations would
      remove the `_ => {}` arms at 225-266 and 268-298. It changes the
      `Arbitrary` decoding and so re-maps the replay corpus: NOT-BP, CARRY.

35. **`pvm/proof/kit/vos_kit.py:292-397` `Manifests.write` (about 105
    lines).** Seams at 295, 322, 330 and 377. The script is part of the kit's
    hash, so CARRY.

## node/venue

The mock is behind `mock`, and conformance is `cfg(test)`.

36. **`kreivo/venue.rs` (929 lines) and `send_anchor` (444-594, 151 lines).**
    BP. FOLD.
    - Extract the gate (454-502) as `fn ready(..) -> Result<(SpaceInfo, u64), Fate>`.
    - Extract the outcome mapping (507-593) as `fn place(..) -> Fate`.
    - `state.later.remove(&key); state.landed.remove(&key);` appears 6 times
      (474, 483, 494, 528, 559, and 175 in `State::held`). Add `State::forget(key)`.
    - Move the send path (435-782) to `kreivo/send.rs`; venue.rs drops to
      about 580.

37. **Test-only venues ship in production, and nothing gates the `mock`
    feature.**
    - No `check-no-*` recipe covers `mock`. Add `check-no-venue-mock`, running
      `_no-feature mock -p vos-cli` with and without `--features prover`, to
      `ci`.
    - Rename the feature to `kreivo-mock`, so `_no-feature` cannot
      false-match third-party "mock" features. That touches
      `node/host/Cargo.toml:66` and `justfile:148`.
    - Add `cargo clippy -p vos-venue --all-targets`. `--workspace` unifies the
      host's dev-dependency feature, so vos-venue without `mock` is never
      linted.
    - BP; this adds a gate. FOLD.
    - `ModelVenue` (`lib.rs:197-497`) and `KreivoVenue` are compiled into `vos`,
      although host, cli and prover use only `VenueClient`, `AnchorRefusal` and
      `StatementId`. Gating `ModelVenue` behind a `model` feature is NOT-BP
      (default API). CARRY.

38. **`kreivo/mock/mod.rs` (1178 lines; `spaces()` at 473-643 is 171 lines).**
    BP, ±0. FOLD.
    - Turn the inline arms into methods, as `register` and `add_authority`
      already are: RemoveAnchorKey (500-512), Migrate (513-537), Resume
      (538-561), DispatchAsSovereign (575-586), SetBudget (587-598),
      SetStatus (618-641).
    - Split into `chain.rs` (44-470) and `pallet.rs` (473-1119).
    - Move `StorageVenue` (:1141, `pub` but used only in the mock; make it
      `pub(crate)`) and the stranded `PAUSE_*` consts (1121-1123) into
      `types.rs`.

39. **`conformance/scenarios.rs` (1567 lines) and `conformance/mod.rs` (828
    lines).** BP. FOLD.
    - scenarios.rs: move 1-475 (consts, `World`, helpers) to `conformance/world.rs`.
      Group the `g*` vectors by theme: anchors (G3-5, G17), submits (G6-10,
      G12, G13), governance (the rest). Leave the bodies whole; they are
      linear scripts.
    - mod.rs: move the JSON schema types (125-405) to `conformance/json.rs`.
      In `step()` (459-551), extract `writes(..)` and `deltas(..)`. Lines
      477-484 compute `fees && key.starts_with(&budget)` twice, inside a
      `match bool`; bind it once and use if/else.

40. **Duplication inside the crate.** BP, about −90. FOLD.
    - The FRAME hashers (`twox64`, `twox128`, `blake2_128`, `*_concat`) are in
      both `calls.rs:527-551` and `mock/keys.rs:15-32,73-80`. The hashers are
      not what the vectors cross-check, so the mock can reuse `calls`' and
      keep its own key layout.
    - `kreivo/transport.rs:198-236`: `retry` and `sign` are the same backoff
      loop. `(wait * 2).min(backoff * 32)` appears 4 times (transport.rs:209,
      230, 259; venue.rs:361). Use a `Backoff` struct, or generalise `retry`
      over `Result<R, SendError>`.
    - `calls.rs:589-613`: the `anchors` and `equivocations` keys have
      identical bodies.
    - `kreivo/tests.rs`: `Lagging` (252-303) and `Counting` (607-646) each
      forward all 9 `Transport` methods. Replace them with one
      `Hooked { inner, on_sign, on_send }`. About −45.
    - `Known` (up to 64 roots plus the keys Vec) is cloned at
      `kreivo/venue.rs:467,718,806,885` where borrows would do. Derive `Copy`
      on `calls::SpaceInfo`, whose fields are all `Copy`, to drop the
      `.clone()` at :398.
    - The genesis read is duplicated (309-311, 352-357), and `Shared::refresh`
      writes `state.now` again at :408 after `venue_now` set it at :335.

41. **Dead code and over-wide visibility.** All checked by grep over the repo.
    BP. FOLD.
    - `calls::PAUSED_REGISTER` (`calls.rs:29`) is unused.
    - `Sender::stopped` (`transport.rs:193`) is `pub` but used only inside the
      module.
    - `Sender.stopping` is an `Arc<AtomicBool>` (171, 180) that is never
      shared; make it a plain `AtomicBool`.
    - `AnchorQueue::spawn_rechecking` (`queue.rs:126`) is used only by the
      tests; make it `pub(crate)`.
    - `kreivo/venue.rs:911-918`: write the match as
      `impl From<SpaceStatus> for Status`.
    - `queue.rs:283-286`: `match bool { true/false }` → if/else.

42. **`calls.rs:345` `Event::SpaceStatusSet { status: u8 }`** and the mock's
    `info.status as u8` (`mock/mod.rs:638`) should use `SpaceStatus`. The SCALE
    bytes are identical, but decoding becomes stricter. BP\*. CARRY, or fold
    both sides together, since the vectors do not change.

## tools/jam-dev, node/jam

43. **`command/statements.rs:161-422` `drive` is 262 lines.** BP. FOLD.
    - Split at its comment seams: deploy (162-220), the large-proof extrinsic
      (222-235), register and anchors (237-293), the fixture statements
      (295-317), equivocation and controls (319-374), migrate (376-389), the
      verdict checks (391-420).
    - `replayed_add` (343-359) repeats `Jam::control` (`venue.rs:198-213`);
      add `Jam::control_at`.
    - Import `Signer` instead of the fully qualified calls at 278 and 352.

44. **Deploying the statements service is duplicated in the e2e and jam-dev.**
    - `node/host/tests/chain/jam.rs:26-36,77-103` and
      `command/statements.rs:70-81,201-220` both run: link → configure →
      `service_blob` → `create_service` → `await_preimage` →
      `Statements::new` → `JamVenue::new`.
    - `ENDOWMENT` and `PREIMAGE_TIMEOUT` appear a third time in
      `testnet/mod.rs:60-64`.
    - `METADATA`'s `env!("CARGO_PKG_VERSION")` resolves to a different crate
      in each copy, so the two deployed blobs differ.
    - **Change:** `vos_jam_dev::live::statements::deploy(..)`. BP, about −35.
      FOLD.

45. **Small jam-dev items.** BP. FOLD.
    - `live/package.rs:284-286`: the doc for `a_package_encodes_as_jamts`
      (:323) sits on `a_packages_payloads_are_read_back` instead.
    - `Jam::land_all` (`venue.rs:224-226`) has no caller.
    - `live/statements.rs`:
      - the slot-to-time formula is written twice (93, 216);
      - `failed(format!("{e:?}"))` appears 3 times;
      - `BTreeSet` is imported at :8 and also written fully qualified at :108.
    - `live/mod.rs` has three separate `use vos_jam::…` lines.
    - `match bool`: `testnet/record.rs:117`, `live/rpc.rs:48`.
    - Doc lines over 100 columns: `venue.rs:13`, `node/jam/src/builder/fit.rs:93`,
      `testnet.sh:23`.
    - `node/jam` `IMPORT_REF` is used only inside its crate; make it
      `pub(crate)`.
    - `testnet.sh`'s `chain` mode does not check up front for the agent,
      test-actor and representative ELFs its header says it needs (only
      48-59 check, for the other modes).

46. **`vos_jam::Error::Node(String)` (`node/jam/src/lib.rs:80-82`)** is now
    built only by jam-dev (`live/mod.rs:108-110`, `venue.rs:220`), left over
    from moving `live` out. Give jam-dev its own error type. NOT-BP (a public
    variant). CARRY.
    - `testnet/mod.rs:178-339` `run` (162 lines, written before this slice):
      CARRY.

## node/host (src)

47. **The leader's anchoring state is spread over 9 loose fields.**
    - `leader/mod.rs:123-152,215-223`: `anchored`, `unanchored`,
      `anchor_tried`, `alerted`, `refused`, `signed`, `foreign`, `seeded`,
      `key_refused`, with full `std::collections::…` and
      `vos_wire::vos_anchor::Anchor` paths.
    - **Change:** one `#[derive(Default)] struct Anchoring` in a new
      `leader/anchor.rs`. Move the anchor half of `close.rs` there: 60-167
      (`anchor_wait`, `handed_back`, `reseed_wait`, `take_up`) and 263-477
      (`seed_waiting`, `anchor_due`, `anchor`, `alert`). close.rs keeps the
      duties, reports and closes (about 190 lines).
    - BP (a move), about −15. FOLD.

48. **Repeated read/decode in `roots`, and other duplication in `leader/close.rs`.**
    BP, about −60. FOLD.
    - "get → `decode_exact` → `map(Some)` → `ok_or(Corrupt)`" appears 6 times:
      `roots/mod.rs:136-143,344-355` and `roots/cuts.rs:229-240,249-258,263-275,486-497`.
      Add `fn decoded<T>`.
    - `unstored(..).and_then(unversioned).ok_or(Corrupt("a value row"))`
      appears 4 times (`cuts.rs:212,292,515`, `mod.rs:680`). Add `fn value_row`.
    - `top.map_or_else(|| empty_root(..), |t| *t.hash())` appears 4 times.
      Add `fn root_of`.
    - `leader/close.rs:190-203,286-298` hand-decode the cut-root scan that
      `roots/cuts.rs:76-86 cut_roots()` already does. Make it `pub(crate)`.
      Also have `cut_root` (229) return the `CutRoot` alias (66).
    - `seed_waiting`:
      - calls `venue.unsettled(&space)` twice (316, 322);
      - computes `space_root(..)` twice (309, 312);
      - collects into a `Vec` and then removes (324-332); use
        `self.signed.retain(..)`.
    - `unsent` (489-496) scans `closings()`, throws the value away, then
      reads each row again through `closing_of`.

49. **Error plumbing and control flow in the leader.** BP. FOLD.
    - `leader/serve.rs:288-290`: `fn fault(roots::Error) -> Fault` is
      imported by its sibling (`close.rs:25`). Make it
      `impl From<roots::Error> for Fault` in `fault.rs`. That drops 7
      `.map_err(fault)` and 3 `fault(Corrupt(..))` calls.
    - `leader/batch.rs:84-106`: three chained `.and_then`s build 2-, 3- and
      4-tuples. Write a `fn duties(..)` with `?`; this also shortens `run`
      (144 lines).
    - `node/queue.rs:48-55,78-86,95`: `Pending::Resume { window, request, served }`
      repeats `Input::Resume` field for field, and every match handles it
      together with `Duty` (`batch.rs:33`, `settle.rs:34,64`). Use
      `Pending::Duty(Input::Resume{..})`. About −15.
    - `leader/serve.rs:220`: an `.expect("the windows")` in production.
      `:266` decodes with `.ok()` where `roots/cuts.rs:346` uses
      `decode_exact`.
    - `leader/cut.rs:47-53,73-79`: closures written and called on the spot,
      `(|| {..})()`; make them `fn`s.

50. **`store/mod.rs`.** BP. FOLD, except the split.
    - **309-310: a misplaced doc.** "The prover's jobs…" sits on top of
      `dump()`'s doc, and `prover_jobs` (332) has none. Move the two lines.
    - The prover-job key `node_record(NodeRow::ProverJob, &[agent_be, id].concat())`
      is built in `store/batch.rs` and at `mod.rs:352-356`, and parsed inline
      at 332-349. Add `keys::prover_job` and a parser.
    - Split 442-617 (`sync_journals`, `clear_unfinished`, `open_tuned`,
      `check_layout`, `Layout`…) into `store/open.rs`: CARRY.

51. **Over-public API and small idioms.** BP. FOLD.
    - Re-exports with no outside user: `lib.rs:45` `genesis_path` and
      `read_genesis`; `roots/mod.rs:54-57` `closing_of`, `serving_windows` and
      `answered`; `Build::finished_cut` and `Build::representing`. Make them
      `pub(crate)`.
    - `self.space.as_ref().and_then(|s| s.genesis())` is written 4 times
      (`node/mod.rs:192,206`, `admin.rs:180`, `api.rs`). Add `Inner::genesis()`.
    - `anchor_keys.rs`:
      - the closure `failed` at :104 duplicates `fn failed` (121-124);
      - `stopped()` returns a secret that its only caller ignores.
    - `host/src/prover.rs`:
      - `match held { true/false }` at 168-171;
      - `std::time::Instant` fully qualified at 300 and 315;
      - `Unrecorded` (40-76) keys by `[u8; 32]` instead of `StatementId`.
    - `lib.rs:206` `Hooks::delay_chunk` names its unused parameters `_to`
      etc., while every other hook uses `let _ = (..)`.

52. **`roots/mod.rs` (777 lines): clean seam at 401.** `Keys`, `Build` and
    `run()` (401-774) → `roots/build.rs`. BP (a move). FOLD.

53. **The idle leader recomputes everything at each wake.**
    - `leader/mod.rs:342-345`: each `*_due()` takes its own snapshot and
      throws its result away, and the batch then computes it all again.
    - `anchor_wait` → `reseed_wait` → `handed_back` (`close.rs:78-108`) checks
      an ed25519 signature on every unsettled anchor at each idle wake.
    - **Change:** one snapshot per `take()`, passed to each `*_due`. Extracting
      `due_now` (330-349) also gives `take` (144 lines) its seam.
    - BP, a performance change. CARRY.

54. **Test-only and stringly API.** CARRY.
    - `Fjall::dump` (`store/mod.rs:314-330`, `#[doc(hidden)] pub`) is test
      tooling; its only user is `checker/carriers/capture.rs:177`.
    - `Result<_, String>` errors: the `Host` and `Jobs` traits
      (`prover/worker.rs:36-70`), `ProveError(String)`,
      `AnchorKeys::rotate`/`rotate_anchor_key`, and the genesis functions.
    - NOT-BP.

## node/prover, node/checker

55. **`RERUN_GAS = 1 << 32` is defined twice:** `checker/src/carriers/needles.rs:66`
    and `prover/src/masked.rs:31`. If they drift, the carrier audit's
    step-count needle searches for the wrong number, and silently so. Export
    it ungated from `vos_node_prover`. BP. FOLD. High.

56. **`worker.rs:548-682` `submit` (135 lines).**
    - Extract `submittable` (550-559) and `judged(..) -> Option<State>` (612-677).
    - `statement.roots.iter().map(|r| r.window).min()` is written twice
      (256-258, 553-556). Add `Job::earliest_window()`.
    - BP. FOLD. The `0x1000` literal is under item 3.

57. **Test-only and dead code in production.** NOT-BP (pub removals), but
    nothing uses them. FOLD.
    - `prover/src/memory.rs` `MemoryJobs` is `pub` and re-exported
      (`lib.rs:58`), and its doc says "a host's…", but only the prover tests
      use it. Move it into `tests/support/`, together with `tests/worker.rs`'s
      fixtures (33-360), which brings that 821-line file to about 460.
    - `Job::id()` (`job.rs:125-127`) has no users.
    - `MaskedProver::prove_timed` (`masked.rs:131-137`) has one caller, which
      drops its `Stats`; inline it.
    - `MaskedProver::kernel` (:64) is used only in-file; make it private.
    - `prover/src/lib.rs` hard-codes "30 s", "three attempts" and "64k entries"
      in prose. Refer to `Options::retry`, `MAX_ATTEMPTS` and `PROVER_HOLD`
      instead.

58. **`job.rs:14-18` `State::Refused(u32)`** mixes the venue's codes with the
    prover's own `REFUSED_RERUN`/`REFUSED_KERNEL`. An enum would change the
    node-local SCALE rows: NOT-BP, CARRY.
    - `work()` reads all jobs about 4 times per step (`worker.rs:235,241,252,284`),
      and `next()` decodes the statement inside `min_by_key` (442-445). CARRY
      (performance).

## agent/* (default, wire, sdk, tree, testkit, test-actors, representative)

`agent/default`, `agent/wire`, `agent/sdk` and `agent/tree` are compiled into
the agent image and the pinned kernels. Every source change there is
**BP-pin**, so CARRY unless it rides a planned re-pin. Changes to
`sdk-macros` that generate the same tokens are BP. The testkit and the
unpinned reader actor are BP.

59. **The reads harness leaves out the committed-writes check.**
    `testkit/tests/agent/reads.rs:206-213` `Reads::batch` compares node and
    model field by field. It repeats `agrees()` (`workflows.rs:366-375`) but
    omits `run.committed`, so no reads test checks the committed writes
    against the model. `representative.rs:130-136` does a partial version of
    the same check.
    - **Change:** move `agrees` to `common.rs` and use it in all three places.
    - About −15. Adding the `committed` check strengthens a gate (NOT-BP in
      that sense) and may expose a divergence. FOLD. High.

60. **`testkit/tests/agent/reads.rs` is 1399 lines.** BP. FOLD.
    - Split into `reads/mod.rs`: the harness (1-460), serving, kernel and
      refusal tests (464-926), pay-for-itself (928-1046, or into
      `pricing.rs`), and `reads/cuts.rs` (1049-1399).
    - `Reads::kernel` (118-126) repeats `programs::kernel`.
    - "Install on node and kit in a space, then sync the version" is written 3
      times: `representative.rs:39-63`, `Reads::new` (66-99),
      `jam/cuts.rs:19-28`. Make it one `common.rs` helper.
    - Split `representative.rs`'s 116-line test at 168 and 180; also, its
      `use crate::common` (:31) sits after code.

61. **`testkit/src/invocation.rs:248-549` `operation` is 302 lines.** This is
    native model code, so BP. FOLD.
    - Pull the `Op::Scan` (327-362), `Op::Call` (363-425) and `Op::Attest`
      (442-508) arms out into methods, matching the default agent's split.
    - Move the read-at-cut methods (593-771) to `invocation/at_cut.rs`.
    - Small fixes:
      - `:685` `let failed = |e| Attested::Failed(e)`; just use `Attested::Failed`;
      - `:760` collects into a `Vec` it does not need;
      - `closes.rs` `stored` (186-195) builds its step by hand instead of
        using `written`.

62. **`sdk-macros/src/messages.rs`: `Handler.reads` and `states_parts()`
    repeat what `kind` already says.** After the refinement at 263-269,
    `reads ⇔ kind == Reading` and `states_parts() ⇔ kind != Attestable`.
    - Drop both and use `kind` at 332, 391, 514, 526 and 594.
    - Split up the long functions: `handler` (174 lines; argument loop
      194-253), `messages_impl` (195 lines; per-handler codegen 357-437),
      `attestable_entry` (104 lines; `parts_body` 514-560).
    - BP if the expanded tokens are identical; check that the program ids do
      not move. FOLD.

63. **Testkit public API and the reader actor.** BP. FOLD.
    - `SPACELESS` (`lib.rs:141`) and `programs::representative_elf`
      (`programs.rs:32`) have no outside users; make them private.
    - `Testkit::install_in` (`lib.rs:193`) takes space and clock separately,
      under `#[allow(clippy::too_many_arguments)]`. Take the
      `(SpaceId, WindowClock)` tuple, as `install_derived_in` does.
    - The `programs.rs` module doc misses `build-representative`.
    - `test-actors/reader/src/lib.rs`: the read closure is repeated 7 times
      (59-61, 74, 88-96, 110-117 ×2, 131-134, 164-167). Add a local
      `fn entries(keys)`. The reader is not pinned.

64. **The attest counter is redundant in both hosts.** `attests_counted` in
    `default/src/refine/invocation.rs` (84, 109, 325, 355, 519, 564, 718, 740)
    and `counted` in `testkit/src/invocation.rs` always equal the sum of
    `if window.is_some() { cap::AT_CUT } else { 1 }` over `attests`.
    - Add `Attest::weight()` in wire. It is a definition, so the testkit may
      share it.
    - Drop the field and the save/restore tuple: about −10 per host.
    - BP-pin. CARRY.

65. **`agent/default`: the row-decode helper is written 3 times, with
    inconsistent strictness.**
    - The copies: `admin.rs:102-106` `row<T>`, `closes.rs:22-27` `read<T>`,
      `invocation.rs:667-677` `space()`.
    - `space()` uses `decode(..).0`, which accepts trailing bytes, where
      `admin.rs` reads the same space and clock rows with `decode_exact`.
    - Other non-exact decodes: `invocation.rs:634` (`asked`),
      `invocation.rs:770-771` (`serves`, `.ok()?`), `invocation/kernel.rs:122`,
      `sdk/src/runtime.rs:152-155`.
    - **Change:** `Base::decoded<T>` with `decode_exact`. A tiny behaviour
      change: rows with trailing bytes are now refused. BP-pin. CARRY.

66. **`agent/wire/src/keys.rs` (987 lines).** BP-pin, about −25. CARRY.
    - Four window-only parsers have identical bodies: `cut_entry` (450-453),
      `cut_root_entry` (529-532), `closing_entry` (652-655), `closed_entry`
      (658-661). Replace them with `window_of`.
    - The `RequestId` layout is written 3 times (457-464, 537-546, 549-551).
    - The `word` closure with `try_into().unwrap_or_default()` is repeated at
      481 and 563.
    - Split the cut/close rows (432-662) into `keys/cuts.rs`.
    - Test-only public API: `closed_entry`, `closed_prefix` and
      `is_replicated` (:967) are used only in tests. And a `moved_prefix()`
      is missing, which forces `keys::moved(0)[..2]` at `reads.rs:223`.

67. **Typed wire fields.** NOT-BP or BP-pin. CARRY.
    - `wire/src/served.rs:80-84` `AgentRoot.kind: u8` sits next to a typed
      `RootRead.kind: RootKind`. Callers compare against
      `RootKind::Space as u8` at 5 sites.
    - The tuple `(AgentId, [u8; 16], Vec<u8>)` (agent, salt, path) has no
      name. It appears in `served.rs:110`, `Input::Close.paths`,
      `default/refine/closes.rs:70`, `testkit/src/closes.rs:80` and
      `reads.rs:336`. Name it `AgentPath`; the SCALE bytes are identical.
    - `tree/src/proof.rs:269-276`: `Entry::BRANCH/HASH/LEAF/EMPTY` are
      `const u8` tags (owner rule); make them an `EntryTag` enum.
    - `default/refine/invocation/ended.rs:43-51`: `Attesting` copies
      `WorkflowState::Attesting` field for field; use `From`.

68. **Long functions in `agent/default`.** BP-pin. CARRY.
    - `refine/batch.rs:218-343` `run_batch` (126 lines): extract
      `fn stepped(..)` (263-324).
    - `refine/invocation.rs` (847 lines): move the read-at-cut half (576-799)
      to `invocation/at_cut.rs`.
      - The kernel-gas fold is written twice (531-535, 724-728).
      - `serves` re-checks `bytes.len() > self.limits.served` (766), which
        its caller already checked (697).
    - Both workflow `step`s open with the same `Resume` match
      (`default/refine/workflows.rs:599-622`, `testkit/src/workflows.rs:327-349`).
      Extract a helper per crate; don't share it across crates.
    - `closes::stored` (`default/refine/closes.rs:137`) returns a `Result`
      that its only caller drops (`inputs.rs:122`). Whether to make it
      infallible or to trap is a soundness call.
    - `sdk/src/runtime.rs:169-174` `verify_served` uses an index loop; use
      `windows(2)`.

69. **`agent/representative` repeats the guest build boilerplate.** Its
    `rust-toolchain.toml` and `.cargo/config.toml` are byte-identical to
    `agent/default`'s, it repeats `[profile.release]`, and it has its own
    218-line `Cargo.lock`.
    - One guest workspace for `default` + `representative` would share them.
      It changes the ELF paths (`testkit/src/programs.rs:16-46`,
      `justfile:172-182`) and possibly embedded paths. BP-pin. CARRY.
    - Do not add an `agent/.cargo/config.toml`: its `build-std` would leak
      into the host crates under `agent/`.
    - Also CARRY: `test-actors/window/src/lib.rs:18-21` carries a
      forward-looking sentence ("as the Clerk's own window will…"), and the
      window kernel is pinned. And these doc lines were never reflowed:
      `wire/src/abi.rs:308`, `default/refine/inputs.rs:172`,
      `wire/src/served.rs:77`.

70. **Served-row and representative-tree fixtures are duplicated across
    crates:** `reads.rs:374-411`, `pvm/proof/tests/kernel/cut.rs:76-127`,
    `node/host/tests/cuts/model.rs`. All of them already depend on
    `vos-testkit`; add a `vos_testkit::served` module. BP. CARRY.

## Tests (node/host/tests, pvm/proof/tests, statement/tests)

71. **The state-prefix list `[[0x00u8], [0x01], [0x03]]` is copied 5 times:**
    `cluster/common.rs:669`, `cluster/cuts.rs:662`, `served/cuts.rs:357`,
    `cuts/model.rs:353`, `node/cli/tests/fault_suite.rs:514`.
    - This slice added `0x03` to one copy and created three new copies. A
      missed prefix quietly weakens the check that replicas agree.
    - The cut-row scan is also copied 3 times (`cluster/cuts.rs:54-65`,
      `served/cuts.rs:344-353`, `cuts/model.rs:314-324`).
    - **Change:** one `keys::STATE_PREFIXES` in vos-wire, or
      `vos_checker::{replicated, cuts}`. A new vos-wire const is
      additive; keeping it in `vos_checker` avoids moving the agent's bytes.
    - BP, about −40. FOLD. High.

72. **The carrier-audit setup is written twice:** `carriers/audit.rs` and
    `chain/run.rs` + `chain/collect.rs`.
    - Identical copies:
      - `Canary` hooks (`audit.rs:80-90`, `run.rs:52-61`)
      - `Frames` (93/65)
      - the `hub.tap` closure (158-166/256-266)
      - the `DEBUG_ENVIRONMENT` `set_var` loop with its SAFETY note
        (127-133/181-188)
      - `log_entries` (338-344/`collect.rs:41-46`)
      - the eight-kind `assert_searchable` list (315-324/`collect.rs:256-265`)
    - Near-identical: the per-node carrier loop (`audit.rs:263-307`,
      `collect.rs:67-97`).
    - **Change:** move them into `vos_checker::carriers` (`Canary`,
      `debug_environment_on`, `node_carriers`, `Kind::ALL`, `finish_logs`),
      and `tap_frames` into `cluster/common.rs`.
    - This also shrinks the 210-line audit test. BP, about −110. FOLD.

73. **`cluster/cuts.rs` and `cluster/representative.rs` are included by
    `#[path]` as helper libraries.** The includes (`carriers/main.rs:21-29`,
    `chain/main.rs:40-48`, under `#[allow(dead_code)]`) compile their 12
    `#[test]`s into two more binaries, and those tests run there whenever the
    binary is run without a filter.
    - **Change:** move the helpers (`cuts.rs:36-100,229-405,655-680`,
      `representative.rs:33-187`) into a test-free support module.
    - BP (a move). FOLD.

74. **Seven hand-written `impl VenueClient` wrappers, each forwarding 6-7 of
    the trait's 8 methods (about 245 lines in all):**
    - `carriers/audit.rs:27-78`
    - `cluster/prover.rs:38-84`
    - `cluster/kreivo.rs:40-88`
    - `cluster/anchor_keys.rs:464-507,537-641`
    - `chain/venues.rs:93-151,234-283`

    `audit::Venue` is `Judging` minus its counter. FOLD merging those two
    (about −40). CARRY a `forward_venue!` macro (about −150).

75. **Repeated cluster helpers.** BP, about −75. FOLD.
    - `chain/agents.rs:78-85` `call` is a verbatim copy of
      `cluster/cuts.rs:274-281`, already compiled in the same binary, and
      `agents.rs:117-121` `agent()` generalises `reader_agent`.
    - `clock.boundary(w).unwrap() + delay(clock) + 1_000` appears 14 times in
      6 files. Add `past_close`.
    - The "wait until the representative's replica closed w" poll appears 3
      times (`anchor_keys.rs:64-86,645-662`, `kreivo.rs:315-329`). Add
      `closed(..)`.
    - The offset clock is written twice (`representative.rs:41-78`,
      `kreivo.rs:107-120,233-239`). Add an `OffsetClock`.
    - The node skew `u64::from(number) * 7` is written 3 times
      (`common.rs:184,392`, `cuts.rs:49`). Add `Cluster::set_clock(s)`.
    - The workload formula (7919/31/9, a request at `version % 10 == 3`) is in
      both `cuts/main.rs:36-76` and `cut_crash.rs:56-95`. Add
      `model::workload`.
    - Kreivo calls are decoded by magic bytes: `cluster/kreivo.rs:287-293`
      `[90,7]`, `chain/measure.rs:120-123`. Decode with
      `RuntimeCall::decode` and match `Spaces(Call::Anchor{..})`.
    - `REPORTED = 90 s` is defined twice (`venues.rs:173`, `collect.rs:37`).
      `/proc/loadavg` is read twice. `cut_crash.rs::check` computes
      `cuts(&before)` twice.

76. **Kernel tests duplicate their fixtures and the worker's mapping.** BP,
    about −85. FOLD.
    - `chain/kernels.rs:32-44` rebuilds the attest → `Statement` mapping "as
      the worker makes it", copying the private `node/prover/src/worker.rs:375-385`.
      If the worker changes, this copy drifts without failing. Export
      `vos_node_prover::statement(attest, program)`.
    - The masked `Statement` is built 3 times (`throughput.rs:80-87`,
      `balance.rs:141-149`, `window_kernel.rs:723-731`), and the pinned model
      venue is set up 3 times. Add `cut::masked_statement` and
      `cut::Venue::pinned`.
    - `ProgramId(program.id().0.map(|w| w.0))` appears at 10 sites; add a
      `From`.
    - `kernel/reads.rs` and `window_kernel.rs` share `map`, `row`, `value`,
      `cut_of` and `large` (reads.rs:81-133, window_kernel.rs:175-235) and
      the `SPIKE_*` constants. Move them to `cut.rs`.

77. **Long test functions and fixed sleeps.** CARRY.
    - `kernel/fixtures.rs:478-874` `generate` (397 lines): split into
      `proofs()` and a data-only `cases()` table.
    - `window_kernel.rs:686-853` (168 lines): extract `proved_window()`.
    - `chain/collect.rs:133-269` `rest` (137 lines).
    - `chain/run.rs:178-310` `Run::start` (133 lines).
    - `anchor_keys.rs` (827 lines): seam at 455, with the hand-back tests
      going to `cluster/handback.rs`.
    - Fixed sleeps that assert "nothing happened", about 33 s of wall time:
      `anchor_keys.rs:722,822`, `kreivo.rs:366,417,421`,
      `cluster/cuts.rs:114,159,182,222`, `prover.rs:323`. A shared
      `stays(what, dur, pred)` would check the invariant throughout the wait
      (slightly stronger, so NOT-BP).
    - The two Kreivo test mocks register a space differently:
      `cluster/kreivo.rs:164-221` writes storage by hand, `chain/kreivo.rs:126-160`
      goes through the calls. Changing that changes the setup path, so
      NOT-BP.

## justfile

78. **The `check-no-*` recipes run `cargo tree` 31 times over about 11
    distinct configurations.**
    - The manifest list `[agent/default pvm/proof/final-verifier/wasm/run pvm/proof/final-verifier/wasm/blob]`
      is written 3 times (`justfile:266` with fuzz added, `284`, `300`).
    - The pair `--workspace` + `-p vos-cli --features prover` is repeated for
      each feature (262-263, 280-283, 298-299).
    - **Change:** one table-driven recipe, mapping each configuration to its
      forbidden features and packages, with one `cargo tree` per
      configuration. Keep the `check-no-*` names as aliases.
    - About −15 lines and about 20 fewer `cargo tree` runs per `just check`.
      BP only if every configuration × feature pair is kept exactly; list
      them in the recipe and diff the sets. FOLD with that check, otherwise
      CARRY.
    - The `mock` gate is item 37.

79. **Other justfile duplication.** BP. FOLD.
    - `check` (431, 433) repeats `test`'s crate list (11) and `test-agent`'s
      (187).
    - The guest flags `--target pvm/proof/statement/riscv64em-vos.json
      -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem`
      appear 8 times.
    - The `statement-service` build line appears 3 times (206, 221, 340).
    - `judge-wasm` repeats its paths 3 times (103-105).
    - **Change:** variables `core_crates`, `agent_crates` and `guest_flags`; a
      `build-statement-service` recipe; a loop in `judge-wasm`.
    - Reflow `:295` (111 columns) and the `test-proof` comment at 66-69.

80. **`test-reads` (440-441) lists 7 test paths as substring filters.** A
    renamed test would match nothing and pass silently. All 7 exist today.
    Group them under one `live::` module, or assert the run count. NOT-BP
    (changes a gate). FOLD.

---

## Fold / carry split

There are 80 items. Most bundle several sites, about 190 sites in all.

| Group | Items | Notes |
|---|---|---|
| **FOLD in 6.x** (BP, cheap) | 1 (host/test/justfile part), 2 (recair, statement-host, fuzz), 3, 4 (host part), 5 (hex), 6–11, 14 (dedupe + heavy split), 15, 16, 26 (`accumulate::kind`, hash-checked), 29 (rig move), 30 (encoders), 32, 33 (names), 34 (two BP parts), 36, 37 (gate + rename + clippy), 38–41, 43, 44, 45, 47–52, 55, 56, 57, 59–63, 71–76, 79, 80, and 78 if the pairs are kept | about −1,100 lines; no program id or proof bytes move |
| **CARRY: re-pin batch** (BP-pin) | 2 (guest crates), 4 (guest part), 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 65, 66, 67 (the BP-pin parts), 68, 69 | slice 7. Fold only if one re-pin of the agent image, the kernels, `final-verify.elf` and the service blob is planned anyway, all in one batch |
| **CARRY: NOT-BP / owner's call** | 12, 26 (`SpaceGenesis::version`), 27, 28, 34 (corpus), 37 (`ModelVenue` gating), 42, 46, 54, 58, 67 (`AgentRoot.kind`) | API, wire, storage or guest-interface changes |
| **CARRY: larger or performance** | 13, 14 (`masked_gates.rs` split), 30 (file split), 31, 35, 50 (store split), 53, 70, 74 (macro), 77 | worth doing; not cheap or not urgent |

## Top 10 by value

1. **Item 59**: the reads harness skips the committed-writes comparison.
   Share `agrees` (a test gap).
2. **Item 55**: `RERUN_GAS` is defined twice, so the audit needle could drift
   silently.
3. **Item 71**: the state-prefix list is copied 5 times; one copy missing a
   prefix weakens the replica-agreement checks.
4. **Item 37**: the `mock` feature has no `check-no-*` gate or no-feature
   clippy, and test venues ship in `vos`.
5. **Item 20**: const-byte tag groups in the statement service and guest
   (owner rule); the verdict tags do not follow `Kind`'s order. CARRY
   (re-pin).
6. **Item 72**: the carrier-audit setup is written twice (about −110).
7. **Items 47, 48**: split the leader's anchoring out of `close.rs`, and the
   repeated decode in `roots` (about −75).
8. **Item 1**: about 60 slice-plan step, pin and spike citations in code
   comments.
9. **Items 36, 38, 39**: the venue crate's three 900–1,600-line files and its
   151/171-line functions.
10. **Item 6**: `prove_once` (223 lines), keeping the rng draw order;
    together with items 43 and 61, the other 250+-line functions.

## Fold order

1. Comments: items 1, 2 (host side) and the misplaced doc in 50. Pure
   text.
2. Gates: items 37, 59, 80, then 78. These change what is checked, so land
   them first and alone.
3. Dead code and visibility: items 7, 8, 26 (`kind`), 41, 51, 57.
4. Tests: items 14, 29, 60, 71–76. Do these before the source moves, so the
   test binaries are cheap to rebuild.
5. Moves: items 36, 38, 39, 47, 52. Mechanical.
6. Duplication: items 3, 4, 5, 9, 10, 30, 40, 48, 49, 55, 56, 62. Run
   `just fixtures` unchanged after 9, the kernel program-id tests after 30,
   and confirm the program ids do not move after 62.
7. Long functions: items 6, 15, 43, 61.

The slice-7 re-pin batch (items 17–25, 64–69, plus the guest half of 2 and 4)
should land as one commit, with one re-pin of the agent image, the kernels,
`final-verify.elf` and the statement-service blob.
