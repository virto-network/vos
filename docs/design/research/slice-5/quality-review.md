# Slice 5 code-quality review (af548eaf..8a66fc3a, tip 8a66fc3a)

Read-only review. No edits or commits. Every line number below is at HEAD.
Each item gives: location, the change, the expected line delta, and whether it
is behaviour-preserving.

- **BP**: behaviour-preserving.
- **BP\***: behaviour-preserving, but it touches an order or byte layout that the
  golden fixtures or program ids pin. Re-run `just fixtures` and confirm the
  fixtures don't change.
- **NOT-BP**: removes tests or public API, or changes a wire format. These are the
  owner's call.

Spot-checked for this report:
- The compact/streaming path has no user outside its own module.
- `analyze_dedup` is used only by a test.
- There are 381 `_pNN` identifiers.
- No format 31 is registered.
- The "prover-trusted for now" comments contradict the constraints next to them.
- Removals left no code remnants: no Ristretto, `poseidon2-channel` or
  `recursion_pcs` code remains. Ristretto survives only in doc comments
  (`proof.rs:118-129,199`, `format.rs:22`, `window/Cargo.toml:18-19`).

## Recorded items, scoped

| # | Item | Scope found | Delta | BP |
|---|------|-------------|-------|----|
| R1 | `*_gate.rs` / `*_negative.rs` grouped under `tests/gates/` | 19 `*_gate.rs` + 4 `*_negative.rs` + `boundary_binding.rs` become one binary, `tests/gates/main.rs` (full plan in item 3) | about −50 | BP |
| R2 | `phase2_alu.rs` renamed | becomes `tests/isa/alu.rs`; delete its local `run_three_reg`, `prove_and_verify` and `test_three_reg_op` (:14-89; the last is `common::prove_three_reg`) and the stale `#[allow(dead_code)]` (:37); fix the citation at `alu_negative.rs:99` | about −90 | BP |
| R3 | `divrem.rs` split (1,059 lines) | `chips/divrem/{mod.rs` (Column 69-217, ~230), `constraints.rs` (232-635, ~410), `witness.rs` (643-846), `trace.rs` (849-1059)`}`; `mul.rs:195-483` and `memory_page.rs:275-534,655-883` should be split the same way | ±0 | BP |
| R4 | `proof.rs` changelog → `docs/status.md` | `proof.rs:32-235`; this also removes the last Ristretto prose (:118-129, :199) | about −204 | BP |
| R5 | `AirColumn` derive → typed `Row<E>` | Has the derive also generate the row view over `ComponentTrace` for `cpu/interaction.rs`. There are 230 `original_base_column!` reads of 147 columns there, and 626 `trace_eval!` reads of 250 columns in `constraints/` (376 re-reads). | about −600 recorded, plus about −350 on the interaction side | BP |
| R6 | `_pNN` suffixes and "now" comments | **Larger than recorded.** There are 91 distinct `_pNN` names (`_p17 _p19 _p20 _p28 _p29 _p31 _p34 _p37 _p40 _p54 _p55`, plus `_p54g`/`_p54k`), 381 uses on 311 lines, in `interaction.rs` 90, `lookups.rs` 87, `program.rs` 66, `signs.rs` 28, `alu.rs` 18, `divrem.rs` 10, `bitmanip.rs` 6 and `memory.rs` 6. "now" wording: see item 1. | ±0 | BP |

## Ranked items

### High

1. **Stale soundness comments that are false.** BP, about −15 lines.
   - `chips/cpu/constraints/compare.rs:141-142` says SetLtS and cmov/min/max are
     "prover-trusted (for now)". The constraints directly below bind them.
   - `constraints/divrem.rs:86-96` is a SHIFT banner inside `divrem()` saying
     "Shifts remain prover-trusted for now". That is false: `alu.rs:209-223`
     (`IsShiftConstrained`, `ShiftQuotient`) and the power-of-2 lookup bind
     shifts. The banner also sits in the wrong function, followed by an empty
     banner pair.
   - `constraints/control.rs:103-106` says "For simplicity, constrain the low
     byte… For now". `branch_conditions` constrains the whole value.
   - Reword the history-style comments: `register_memory.rs:81,192`,
     `memory.rs:74`, `register_memory_closing.rs:53-56`, `jump_table.rs:2-3`,
     `constraints/divrem.rs:161`, `mul.rs:129`, `cpu/columns.rs:839`
     ("Stwo-v2.x").
   - `cpu/CONSTRAINTS.md:57-58` repeats the same wording.
   - **Do this first. An auditor reading these comments would think the AIR is
     unsound.**

2. **Process narrative in code.** BP, about −40 lines.
   - recair:
     - `recair/src/verifier/oods.rs:2` "(slice 5's 5.9)";
     - `recair/src/fold/child.rs:6` "5.9's compiler";
     - `recair/src/wrap.rs:8` "5.10's pieces";
     - `recair/src/lib.rs:1` "§10 step 1";
     - `recair/tests/gates.rs:1` "Step 5.8's gates";
     - `recair/tests/leaves.rs:1` "first feasibility gate (§10, step 4)";
     - `recair/tests/compiler.rs:12-13,55`, a `research/slice-5/` path.
   - pvm/proof/src:
     - `format.rs:61` "until slice 6";
     - `segment.rs:1575,1716,1780` "W2.2", "W2(a)";
     - `framework/traits/erased.rs:87` and `prove/canonical.rs:18,184`
       "federation wire-through W0";
     - `proof.rs:1084` "Track B";
     - `verify.rs:323` "(format v5)";
     - `boundary_binding.rs:44-64` "v6", "now", "previously".
   - verifier:
     - `verifier/src/lib.rs:590-599,642-660` "v7:", "(format v5)", "(v6: …)";
     - `verifier/tests/standalone.rs:356,421,513,551` "Phase 42/49/43";
     - `verifier/tests/measure_finish_line.rs:1-16,80,109` "Track A/B"; rename
       the file to `segment_cost.rs`.
   - "// Memory is now flat_mem in Interpreter" appears in `tests/memory.rs:5`,
     `control_flow.rs:5`, `add64_e2e.rs:5`, `phase2_alu.rs:5` and
     `verifier/tests/standalone.rs:6`.
   - `tests/memory_merkle_gate.rs:8` "Phase-A".
   - `register_memory.rs:330-332` "B5".
   - Measurement narrative belongs in `docs/status.md` or the benches:
     `prove.rs:139-146` (thread-pool table), `:177-178` ("beat Nexus zkVM
     2.x"), and `:242,874-875,993-996` (Ristretto-era timings).
   - Algorithmic "Step N" comments in `blake2b/{mod,columns,trace}.rs` (the G
     function's steps) and "fold step" (a FRI parameter) are fine.

3. **Group the pvm/proof test binaries: 47 → 5.** Each binary links the prover,
   and `common/mod.rs` (565 lines, `#![allow(dead_code)]` at :8) is compiled
   into all 47. BP, about −50 lines and far less linking.
   - `tests/gates/main.rs` (24 files): the 19 `*_gate.rs`, the 4 `*_negative.rs`
     and `boundary_binding.rs`. The `debug-internals` modules stay
     `#[cfg]`-gated inside it.
   - `tests/isa/main.rs` (11 files): `alu` (was `phase2_alu`), `add64_e2e`,
     `bitmanip`, `control_flow`, `cpu_completeness`, `loads_signed`, `memory`,
     `host_call_pc`, `precompiles`, `witness_input`, `chip_isolated`.
   - `tests/kernel/main.rs` (7 files): `kernel_shape`, `window_kernel`,
     `fixtures`, `program_identity`, `prove_chain`, `chain_standalone`,
     `recursion_seams`.
     - It installs the `#[global_allocator] Counting` once; today
       `kernel_shape.rs:18` and `window_kernel.rs:21` each install it.
     - The leaf/fold/wrap/JAM helpers move out of `common` into this binary.
   - `tests/settle/main.rs`: `settle_fixture`, `settle_run`, `settle_transpile`.
     The last two duplicate the ELF load (about −10). Moot if item 6(b) is done.
   - What must change with the grouping:
     - `justfile:66` `--test fixtures the_fixtures_are_the_generators` becomes
       `--test kernel fixtures::the_fixtures_are_the_generators`.
     - The child-process gates run `--exact <name>`. In a grouped binary that
       name needs its module path, so build it from `module_path!()` in the
       shared `in_child`.

4. **Gate helpers copied file to file** → `tests/gates/common.rs`. BP, about
   −380 lines.
   - `in_child`: 10 copies, 19 lines each (e.g. `blake2b_gate.rs:47`,
     `cpu_soundness_gate.rs:120`); `cpu_halt_gate.rs:40` is a variant.
   - `assert_chip`:
     - 6 identical 8-line copies (`jump_table:42`, `operand_binding:85`,
       `memory_ledger:62`, `cpu_halt:26`, `page_permission`,
       `witness_input_gate`);
     - 4 identical 20-line `Result` copies (`blake2b_boundary:39`,
       `cpu_ts_chain:40`, `ledger_readconsistency:50`, `memory_merkle:51`);
     - 4 variants.
   - `stored`: 7 copies plus 2 variants.
   - `find_row`: 4 copies.
   - `set`/`get`/`set_field`: about 7 copies.
   - `common/mod.rs:92` `prove_and_verify_with_debug` has no callers (−18).
   - Local `prove_and_verify` copies: `control_flow.rs:11` and `memory.rs:14`.
   - The standard-program builder is repeated in `witness_input_gate.rs:28`,
     `witness_input.rs:54`, `fixtures.rs:115`, `kernel_shape.rs:296` and
     `recair/tests/common/kernel.rs:23`; one `common::standard_program` (−70).

5. **recair tests: 10 binaries → 1 or 2, plus shared helpers.** BP, about −200
   lines.
   - Binaries: `tests/circuit/` (gates, gate_vm, modes, compiler) and
     `tests/recursion/` (leaf, leaves, leaf_rows, verifier, fold, wrap).
   - Split along the files' existing sections:
     - `compiler.rs` (1,162 lines): `real` 808-1037, `synthetic` 1040-1162;
     - `verifier.rs` (1,157 lines): the per-piece tests at 705-1157 become
       their own module.
   - Move into `common`:
     - `print_rows`: 4 copies (`fold.rs:198`, `leaf.rs:103`, `leaves.rs:100`,
       `verifier.rs:253`);
     - `position_of`, `bump`, `first_refusal`, `panic_message`: in both
       `leaves.rs` and `verifier.rs`;
     - the transcript-equals-recorder assertion: 4 copies (plus
       `pvm/proof/tests/common/mod.rs:335`);
     - the prove + `circuit_commitment` + verify roundtrip: about 10 sites;
     - the full-shape Add64 proof: built twice (`compiler.rs:999-1037`,
       `verifier.rs:139-178`); build it once behind a `OnceLock`.
   - Duplicated constants:
     - `WINDOW_MASK`/`WINDOW_LOG_SIZES` at `leaves.rs:301`, `verifier.rs:273`
       and `leaf_rows.rs:175`;
     - `const QUERIES = 40` at `leaves.rs:305` should use
       `vos_pvm_compiler::leaf::QUERIES`.
   - Copies of what `vos_recair` already exports:
     - `common/mod.rs:194` `pack` = `vos_recair::verifier::witness::pack`;
     - `verifier.rs:79` `Real::drawn` = `witness::drawn_positions`;
     - the `Rng` at `leaf_rows.rs:157` = `common::Rng`.

6. **The leaf → fold → wrap pipeline is written three or four times in tests.**
   Copies: `recair/tests/fold.rs:50-170`, `wrap.rs:52-150`, `leaf.rs:42-100`
   and `pvm/proof/tests/common/mod.rs:296-506` (`prove_leaf`, `prove_fold`,
   `wrap_root`). Add `vos_recair::tree` (`Node{proof,output}`, `proved()`,
   prove leaf/fold/wrap). Slice 6 (Clerk) needs it anyway. BP, about −150 test
   lines and +60 src.

7. **One recursion-AIR transcript prefix.** BP\* (the golden wraps pin it),
   about −45 lines.
   - The same sequence is written three times: `final-verifier/src/lib.rs:241-283`,
     `recair/src/prove.rs:364-398` and `recair/src/fold/child.rs:184-215`. Each
     does header, preprocessed root, main root, outputs or words, interaction
     PoW, `GateRelation::draw`, claimed sums, interaction root.
   - The six-step transcript doc is copied at `final-verifier/src/lib.rs:12-19`
     and `recair/src/prove.rs:7-16`.
   - Move `mix_header` (`final-verifier/src/lib.rs:304-322`) and a generic
     `replay_prefix<MC>` into `vos_recair_air::transcript` (no_std).
   - Related, in the native recursion seams (`src/verify/recursion.rs`):
     - the lifting-height derivation is recomputed at :104-112, :451-463 and
       :750-760, while `proof::derive_protocol_degree_shape` (`proof.rs:726`)
       already does it checked;
     - the Stwo verifier head (random_coeff → composition commit → oods_point)
       is replayed in both `reconstruct_oods_on` (:80-185) and `replay_stark`
       (:431-485);
     - extract `verifier_head()`: about −40, BP.

8. **Module splits over 1,000 lines.** BP, ±0 apart from the removals noted.
   - `src/segment.rs` (1,908 lines; the whole prover is one inline
     `mod prover {}` at :56-1265) becomes `segment/`:
     - `bounds.rs` (:59-340), `window.rs` (:360-580), `cursor.rs` (:580-835),
       `stream.rs` (:835-1265), `tests.rs` (:1275-1908);
     - the docs at :12-35 are false: they say memory continuity "trusts the
       prover" and `verify_chain_standalone` is future work, but `memory_root`
       is bound and the verifier crate has it at `verifier/src/lib.rs:746`.
   - `src/proof.rs` (1,263 lines), after R4:
     - preflight → `proof/preflight.rs`, about 590 lines (:412-1003);
     - PCS/security policy → `proof/policy.rs`, about 200 lines (:1062-1263);
     - leaves about 260 lines.
   - `chips/cpu/trace_fill.rs:42` `generate_main_trace` is **one 1,725-line
     function**. Split along its own markers into
     `trace_fill/{operands,alu,compare,shift,control,divrem,memory,host_call}.rs`
     (operands 50-195, add/sub 195, mul 220, bitwise 325, compare 358, shift
     507, flags 545, jumps 655, divrem 736, memory 841-1040, host calls 1044).
   - `chips/cpu/interaction.rs:38` is one 1,435-line function. Split at 281,
     450, 505, 573, 919, 967 and 1157.
   - `chips/blake2b/mod.rs` (1,716 lines): the compression core it shares with
     `boundary.rs` goes to `blake2b/compression.rs` (175-821, a 646-line
     function to split at its G-step markers; 989-1210; 1220-1491).
   - `src/page_merkle.rs` (1,155 lines): tests at :643-1155 →
     `page_merkle/tests.rs`.
   - `src/refine/prover.rs` (1,202 lines) shrinks under item 11.
   - `src/core/tracing.rs` (1,102 lines) shrinks under item 10.

9. **Lookup tuples listed twice by hand.** BP\* (keep the entry order), about
   −300 lines.
   - The constraint side (`constraints/lookups.rs`: `mul_lookup`,
     `divrem_lookup`, `compare_lookup`, `bitwise_lookup`) and the interaction
     side (`interaction.rs:1157-1402`) list the same columns separately. The
     divrem tuple is 41 columns at `lookups.rs:183-208` and again at
     `interaction.rs:1230-1255`.
   - Replace with `const …: &[Column]` lists plus `tuple_eval` and
     `tuple_packed` helpers. This removes the risk of the two sides drifting
     apart.

### Medium

10. **`src/core/tracing.rs:544-897` `decode_mem_access`.** Its 20 arms are 6
    argument shapes times 4 widths. Use one `access_width(opcode)` plus one
    match per shape. BP, about −270.
11. **`src/refine/prover.rs:970-1049` `observed_step` duplicates
    `TracingPvm::step`** (`core/tracing.rs:122-218`): decode, register indices,
    `recorded_write`, gas, next pc and memory access. Extract one
    `record_step`. BP on valid traces. The error paths unify: the tracer uses
    unchecked gas and `usize` pc arithmetic, the observer checked and wrapping
    arithmetic. About −50.
12. **Uncalled code in the ledger chips.** BP, about −800.
    - `register_memory.rs:468-1119`:
      - `RegisterDedupReport` and `analyze_dedup` (476-677) have no callers;
      - `B5_MERGE_CAP`, `MergedRegEntry` and `merge_entries`/`unmerge_entries`
        (680-798) are kept "as documentation", with 11 tests (800-1119);
      - keep `build_entries_from_side_note` (513-603) and move the note to
        `ledger-read-consistency.md`;
      - about −600.
    - `memory.rs:436-662`:
      - `MemoryDedupReport`/`analyze_dedup` are used only by the test at
        `page_merkle.rs:914`;
      - their entry collection (477-548) copies the trace generator's
        (676-760); extract one `ledger_entries` and give the test a small page
        counter;
      - about −200.
13. **Three copies of the chip list**: prover `BASE_COMPONENTS` (`lib.rs:290`),
    verifier `BASE_COMPONENTS` (:327) and the `drive_chip_oods` match
    (`framework_access.rs:188-214`). The `chip_idx` order is a fourth copy, and
    `pvm/compiler/src/shape.rs:27` `pub mod chip` (25 constants) a fifth, held
    equal by the test at `kernel_shape.rs:147-180`. Generate them with one
    `chips!{}` macro and put one constant table in `vos_wire::records` next to
    `SEGMENT_CHIPS`. BP\*, about −120.
14. **The mask-to-components selection is repeated six times**:
    `prove/shaped.rs:16`, `prove.rs:484-487`, `verify/recursion.rs:223-230,694-701`,
    `framework_access.rs:131`, and the inverse at `prove.rs:886`. One
    `pub(crate) fn chips_of_mask`. BP, about −25.
15. **The preprocessed commit and twiddles are built in four places**:
    `prove.rs:700-718`, `:905-937`, `prove/canonical.rs:129-147` and
    `verify.rs:456-477`. `verify_preprocessed_trace` can call
    `program_commitment_on`, and `prove_on:914-929` can call
    `mix_statement_header` instead of inlining it. In
    `recair/src/prove.rs:158-162,209-213` the twiddles are duplicated, and
    `:264-277` duplicates `vos_recair_air::committed_log_sizes`. BP, about −60.
16. **settlement-verifier.**
    - (a) `lib.rs:54-175` copies `P2Hash`, `P2MerkleHasher`,
      `Poseidon2M31Channel` and `P2MerkleChannel` from `vos_pvm_proof::poseidon2`,
      which it already depends on. Re-export them and drop the equality test
      at :402. BP (`settle_run` gas may move slightly), about −150.
    - (b) Retire the crate: the statement guest `final-verify.elf` now runs a
      real wrap verify on the PVM, while this crate verifies a toy AIR.
      NOT-BP, about −1,600 including its lock, tests, `riscv64em-vos.json`
      (byte-identical to `statement/`'s) and `justfile:46-50,69-73,91,167`.
17. **Compact/streaming trace path with no consumer** (spot-checked):
    `CompactTrace`, `CompactSegmentCursor`, `TraceStream`, `StepSource`,
    `TracingSource`, `segment_bounds_budgeted_compact`,
    `canonical_profile_for_bounds_compact`, `NaturalFloors`, `into_compact`,
    `take_step`. The only non-test reference anywhere is the re-export at
    `lib.rs:594`. Its consumer was the "prover-extension" crate, which no
    longer exists; `lib.rs:34,91,103` and `prove/canonical.rs:157` still cite
    it. NOT-BP (public API), about −900. If it stays:
    - `segment.rs`'s single-stream scaffolding (`StreamCursors{blake2b}`
      :688-705, `drain_stream` :821, `pop_pair` :901, `filter_pair` :1245)
      could be inlined (BP, −35);
    - the advance loops copied at :661, :797 and :1228 could share one helper
      (BP, −30).
18. **The CPU relation bag**, `cpu/mod.rs:73-160`: a nested 17-element tuple,
    destructured and rebuilt into `constraints::Lookups`. Make `Lookups` an
    owned struct that implements `ComponentLookupElements`. BP\* (the draw
    order is consensus-relevant per 2ef8f36b), about −70.
19. **Blake2b column duplication**: two hand-written `CompressionColumns`
    impls (`columns.rs:605-716`, `boundary.rs:474-587`), and `BoundaryColumn`
    (`boundary.rs:222-474`) restates the shared variants. Generate them with
    `macro_rules!`. BP\* (the column order is part of the program's identity),
    about −250.
20. **`classify.rs:236-797` `classify_opcode`** (562 lines, 98 arms). Derive the
    category flags after the match and write the arms as struct literals with
    `..Default`. Add an all-opcodes equality test against the old table. BP,
    about −300.
21. **`trace_fill.rs:1627-1742` `CPU_DUMP`**: 115 lines with a hand-written
    list of 88 columns, two copied row loops and a `std::env` read in the
    prover. Make it a generic dump over `C::ALL_VARIANTS`, or delete it. BP
    for proofs, about −100.
22. **Public API with no workspace user.** NOT-BP (API):
    - `vos-pvm-proof`: `verify_with_options` and `verify_with_max_log_size`
      (`verify.rs:90,114`), `canonical_profile_for`, `prove_chain_format`,
      `natural_log_sizes_for`, `ComponentLayout`, `DeepBatch`, and the
      `MOBILE_MIN_*` re-exports (`lib.rs:556`);
    - verifier crate: `verify_standalone_with_options` (:404),
      `verify_chain_standalone_with_options` (:775) and
      `verify_chain_standalone_allowlist` (:859);
    - `debug-internals`: `debug_*_streaming` (`prove/debug.rs:110-223`).

    About −250 in total. Separately, the chain-continuity loop with the same
    error is written three times (`verifier/src/lib.rs:819,885,993`); one
    `check_continuity` helper is BP.
23. **pub → pub(crate).** BP.
    - vos-recair, functions with no external user: `check_total`,
      `constant_point`, `decompose_word`, `double_x`, `draw_felt(s)`, `h8_into`,
      `io_hash_limbs`, `lane_sum`, `leaf_circuit_hashes`, `m31_of`, `mix_wire`,
      `preimage_wires`, `verify_path`, `verify_rest`, `words_of`,
      `preprocessed_root_on`.
    - vos-pvm-poseidon2: `pow_passes`, `INTERNAL_DIAG_SHIFTS`,
      `INTERNAL_DIAGONAL`.
    - vos-pvm-compiler: `shape::host_call_chips` (:117) and
      `leaf::oversized_leaves`; inline `oversized` (:742-754), which has one
      caller.
    - Also consider moving `verify/recursion.rs` (826 lines; its only
      consumers are vos-recair and tests) into vos-recair.
24. **Thin wrapper layers.**
    - `prove.rs:431-540,797-830`: `prove_impl` → `…_with_components` →
      `…_overridden` → `prove_on`, two of them with 8 arguments. Use one
      options struct. BP, about −40.
    - `BuiltInProverComponent` (`framework/traits/builtin.rs:74-117`) has four
      main-trace methods, and 11 chips write the same `_immut` →
      `_immut_min(sn, 0)` forwarder. Keep the `_min` pair. BP, about −50.
    - `recair/src/verifier/shape.rs:58-97`: the `HeaderWords` fake `Channel`
      (six `unreachable!`s) becomes a `statement_header_words()` that
      `mix_statement_header` iterates. BP, about −30.
25. **Other duplication.**
    - `refine_codec.rs:295-390,539-550` `encode_*` are byte-identical to
      `refine/encode.rs`'s `put_*`; −45.
    - `page_merkle.rs:95-180` (`default_hashes`, `subtree_root`,
      `sparse_root`) re-implements `vos_pvm_program::image::root`; −45.
    - `core/tracing.rs:15-20`: `Blake2bRecord` is a field-for-field copy of
      `Blake2bCall`; −25.
    - `P2Hash` ↔ `Digest` conversions are written by hand at 8 sites; add
      `to_digest`/`From`; −10.
    - The blake2b-call register list `[10,7,8,9]` appears at
      `host_call.rs:122` and `interaction.rs:375`, and is hard-coded in
      `reg_access.rs:169-175`; −12.
    - The 28-bit ordering decomposition is in `memory.rs:43,868-890` and
      `register_memory.rs:49,410-425`; −25.
    - All BP.
26. **Misnamed columns**: `cpu/columns.rs:303-330` `Phi10/11/12/7` hold
    φ7/8/9/10, and a comment there admits it. Rename them to
    `HPtr/MPtr/TLow/Flag`; 78 references in 8 files. BP.
27. **Crate names.** `vos-recair`, `vos-recair-air`, `vos-final-verifier`,
    `vos-final-verifier-wasm(-run)` and `vos-statement` break the
    `vos-pvm-*` pattern that 5.8.0 applied to `vos-pvm-poseidon2`. Rename them
    to `vos-pvm-recair`, `vos-pvm-recair-air` and `vos-pvm-final-verifier*`.
    Keep `vos-statement`'s name only if it is deliberately VOS-independent for
    the pallet. BP in behaviour; imports and justfile change.
28. **Format references.**
    - `verifier/tests/formats.rs:4` says "Format 31 proves on the Poseidon2-M31
      channel", but 31 is not registered; that is format 35 (`format::SEGMENT`).
    - `format.rs:33-37` contradicts itself on 32.
    - `prove.rs:199` says `Target::legacy` is "Format 24"; it is 36.
    - Bare numbers in docs (`leaf.rs:25`, `tests/common/mod.rs:461,505`,
      `window_kernel.rs:16,700`, `kernel_shape.rs:499`, recair tests) should
      name the `format::` const.
    - BP.

### Low

29. **Dead code.** BP, about −45.
    - `framework_access::drive_cpu_chip_oods` (:221-228);
    - `air_column/empty.rs`;
    - `LogupTraceBuilder::add_to_relation` (`#[allow(dead_code)]`);
    - `trace/builder.rs` `column_mut`, `trace/utils.rs` `zero_array`,
      `trace/eval.rs` `shared_preprocessed_column`;
    - `precompiles/src/blake2b.rs:153-155` `let _ = &mut param_lo`.
30. **Dead `let _ = x` reads**: `constraints/compare.rs:236`,
    `host_call.rs:146`, `signs.rs:56,222`, `registers.rs:251-252`,
    `constraints/divrem.rs:303`, `trace_fill.rs:1236,1528`,
    `power_of_two.rs:115`, and chip `compare.rs:229`. Drop them along with the
    reads that feed only them. `trace_eval!` has no side effects. BP, about −20.
31. **Stale cross-references from the CPU split.**
    - "near end of / top of add_constraints": `bitmanip.rs:73-74,115,121`,
      `program.rs:152-154`;
    - "helper block above": `control.rs:121-123`, `registers.rs:225,360`,
      `host_call.rs:144,194`;
    - `mod.rs::ECALL_REG_IDXS`: `reg_access.rs:155`, `interaction.rs:367`,
      `columns.rs:307`.

    BP, about −10.
32. **Stale docs.**
    - `lib.rs:2` "Kunekt actor runtime";
    - `lib.rs:291-311` "producer-only until…" and "dormant until…";
    - `lib.rs:254-266,401-403` describe Blake2b as the only optional chip;
      there are 9;
    - missing files cited: `STWO_PHASE_I_BLAKE2B.md` (`prove.rs:450`,
      `tests/chip_isolated.rs:9`) and `STWO_2.2.0_MIGRATION.md`
      (`prove.rs:127`);
    - `settlement-verifier/Cargo.toml:4` cites a moved doc;
    - `window/Cargo.toml:18-19` mentions "Ristretto precompiles";
    - `pvm/proof/docs/design/ristretto-ts-binding.md` (status: removed) can be
      deleted, and `memory-merkle-binding.md:205` cites deleted tests.

    BP.
33. **Banners and imports.**
    - 65 `// ════` banner lines in `constraints/*` restate the function docs
      (−60).
    - `#[allow(unused_imports)]` on the `alloc` import in 26 chip files; use a
      crate prelude.
    - Import the `trace_eval!` macro instead of writing the full
      `crate::trace::trace_eval!` path at 626 uses (moot after R5).
    - BP.
34. **Small idioms.**
    - Empty-trace early returns that equal the general path:
      `compare.rs:173`, `mul.rs:514`, `bitwise.rs:237`, `divrem.rs:864`;
      `MIN_LOG_SIZE = 5` repeated 4 times; −40.
    - `ceil_log2_at_least_lanes` (`trace/utils.rs:19`) uses f64 `log2`; use
      `ilog2`.
    - `proof::MAX_PROOF_LOG_SIZE`, `verify::DEFAULT_MAX_LOG_SIZE`,
      `shape::MAX_LOG_SIZE` and the verifier crate's constant are four
      constants for one cap of 24.
    - `MemoryLayout`/`REGIONS` move out of `chips/memory_page.rs:73-163`, and
      `permission()`'s 0/1/2 becomes a `#[repr(u8)]` enum.
    - `agent/tree/src/hash.rs:51-60` should use `array::from_fn`.
    - `agent/tree/src/encoded.rs:95,115,123,158` match on the `Entry` tag bytes
      0-3; make them named constants shared with the codec.
    - `tracker/src/main.rs:39` `Probe.arguments` → `input`.
    - `pvm/compiler/src/leaf.rs:629-733` `leaf_terms` uses unnamed constants;
      name each after the verifier piece it counts.
    - `vos-pvm-precompiles`' only feature, `blake2b`, is its default and its
      whole content; drop it and use `{ workspace = true }` in the 12 manifests
      (−15).
    - All BP.
35. **Long functions to split, ±0.**
    - `pvm/compiler/src/leaf.rs:434` `deep()` (135 lines);
    - `pvm/compiler/src/derive.rs:614` `kernel()` (150 lines);
    - `recair/src/compile/program.rs:100` `lower` (160 lines);
    - `recair/src/verifier/deep.rs:100` `DeepPlan::new` (139 lines);
    - `recair/src/verifier/stark.rs:391` `verify_rest` (131 lines);
    - `verifier/src/lib.rs:134` `verify_refine_bundle_authenticated` (207
      lines).

    Also add `Derived::derivation(elf)` to `derive.rs` to replace the four
    six-argument `Derivation::new` call sites (testkit, cli, host, jam; −20).
    All BP.

### NOT-BP removals for the owner to decide

- Item 16(b): retire settlement-verifier (about −1,600).
- Item 17: delete the compact/streaming path (about −900).
- Item 22: the public API with no workspace user (about −250).
- Delete the spike toy-AIR tests `tests/poseidon2_m31_channel.rs` (370 lines)
  and `tests/qm31_constraints.rs` (186 lines). recair-air's `qm31` and the
  production channel tests (`verifier/tests/formats.rs`, `recursion_seams.rs`)
  supersede them.
- Retire `pvm/proof/verifier-wasm-bench` (about −3,200 with its lock). The
  final verifier's Wasm runner supersedes it, and only the justfile's fmt list
  references it.
- Drop the relabel seam for the retired formats 18/19 (`prove.rs:771-795`,
  `transcript.rs:27,170-179`; about −45). This removes the test at
  `standalone.rs:389-406`.
- Fuzz `final_verifier_mutate.rs`: merge the `Grow`/`Shrink`/`Clear` variants
  into one. This invalidates the existing corpora.

## Suggested fold order for 5.16

1. Comments: items 1, 2, 28, 31, 32 and R6. Pure text, no risk.
2. Dead code: items 12, 29 and 30, and R4.
3. Tests: R1, R2 and items 3-6. Do these before the src splits, so the test
   binaries are cheap to rebuild.
4. Module splits: R3 and item 8. Mechanical moves.
5. Duplication: items 7, 9, 10, 11, 13-15 and 25. Run `just fixtures`
   unchanged after each BP\* item.
6. The `AirColumn` `Row<E>` derive (R5) last; it makes item 33's macro-import
   change unnecessary.

Expected BP total is about −4,000 lines. The owner-decided NOT-BP removals add
about −6,000 more.
