//! Phase I.0 — chip-isolated prove harness smoke tests.
//!
//! These tests validate `prove_with_explicit_components` /
//! `verify_with_explicit_components`: the harness used to validate each
//! Phase-I chip rewrite independently before all 5 high-bound chips are
//! flattened.  See `crates/zkpvm/STWO_PHASE_I_BLAKE2B.md` for context.
//!
//! The smoke test below uses only bound-1 chips (already at degree ≤ 2).
//! It must pass on the new Stwo pin (`e1286720`) — if it doesn't, the
//! harness wiring itself is broken and no chip-rewrite validation can
//! proceed.

use zkpvm::{
    chips, harness::MachineProverComponent,
    prove_with_explicit_components, verify_with_explicit_components,
    FriConfig, PcsConfig, PcsPolicy, SideNote,
};

/// Minimal bound-1-only configuration.  These chips all declare
/// `LOG_CONSTRAINT_DEGREE_BOUND = 1` (default) so they work on the v2.x
/// lifted protocol without any rewrites.
///
/// Picked for: simple boundary semantics, no cross-chip lookup
/// dependencies that need closure with an empty side_note.
const BOUND1_HARNESS_COMPONENTS: &[&'static dyn MachineProverComponent] = &[
    &chips::RangeMultiplicity256,
];

/// Smoke test: prove + verify a no-op trace through the harness API.
///
/// `RangeMultiplicity256` is a static lookup table — it produces all
/// 256 byte-range entries with multiplicities tied to consumer demand.
/// With no consumers in the component slice, multiplicities are all
/// zero, claimed_sum is zero, and the lookup balance trivially closes.
///
/// What this validates:
/// - `prove_with_explicit_components` wires the explicit slice through
///   to `prove_impl_with_components` correctly.
/// - `verify_with_explicit_components` re-runs preprocessing and
///   verifies the same slice.
/// - The bumped Stwo pin (`e1286720`) accepts a bound-1 AIR cleanly.
///
/// What this does NOT validate:
/// - High-bound chip flattening (Blake2b/Mul/DivRem/Cpu/Ristretto are
///   not in scope; their tests come once each is flattened).
/// - Lookup balance closure across chips (that needs the eventual
///   Phase-I.0 sink components — out of scope for this smoke test).
#[test]
fn harness_smoke_bound1_only() {
    let mut side_note = SideNote::new(Vec::new(), Vec::new(), Vec::new());

    // Minimal valid PcsConfig — fast prove for a smoke test.
    let config = PcsConfig {
        pow_bits: 5,
        fri_config: FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };

    let proof = prove_with_explicit_components(
        &mut side_note, config, BOUND1_HARNESS_COMPONENTS,
    ).expect("harness smoke: prove failed on bound-1 AIR — wiring bug");

    // Build the verifier-trait slice via upcast.
    let verifier_components: Vec<&dyn zkpvm::harness::MachineComponent> =
        BOUND1_HARNESS_COMPONENTS.iter()
            .map(|c| *c as &dyn zkpvm::harness::MachineComponent)
            .collect();

    // Cheap policy matching the cheap PcsConfig — production verify
    // would use PcsPolicy::STANDARD; the harness needs to accept its
    // own cheap config to keep chip-rewrite validation cycles fast.
    let policy = PcsPolicy { min_pow_bits: 5, min_fri_queries: 3, min_fri_log_blowup: 0 };

    verify_with_explicit_components(
        proof, &side_note, &verifier_components, BOUND1_HARNESS_COMPONENTS,
        &policy,
    ).expect("harness smoke: verify failed on bound-1 AIR — wiring bug");
}

/// Phase I.0 — Blake2bChip-isolated harness for the I-blake2b-N chip
/// rewrite work.  The intended green state once Phase I lands:
///
/// - `prove_with_explicit_components([&Blake2bChip], ...)` SUCCEEDS
///   (chip's algebraic constraints all degree ≤ 2 after flatten).
/// - `verify_with_explicit_components(...)` REJECTS with
///   `claimed logup sum is not zero` because the chip emits
///   bitwise/range/mem/blake2b_call lookup contributions with no
///   producer chips in scope to balance them.
///
/// Open-chain rejection is the chosen validation pattern (vs. building
/// a sink chip that produces phantom balancing tuples) because:
///
/// - Open-chain catches every algebraic-constraint regression (OODS
///   sanity check fires on `ConstraintsNotSatisfied` before lookup
///   balance is even checked).
/// - Sink-chip closure adds ~100+ lines of test-only chip code per
///   high-bound chip — trades reviewable scope for marginal extra
///   validation (lookup tuple correctness, which the existing
///   integration tests on the OLD pin already covered).
/// - When the full migration completes and `prove_add64` runs through
///   the production path, lookup correctness is checked end-to-end.
///
/// CURRENT STATE: chip algebra FLATTENED to degree ≤ 2; this harness
/// passes (open-chain rejection at verify).  An upstream Stwo bug —
/// `MerkleProverLifted::decommit` index OOB on mixed-width column
/// traces — is documented in `STWO_MERKLE_LIFTED_OOB_ISSUE_DRAFT.md`
/// (not filed; not blocking — bound-1 + this harness shape no longer
/// trips it, and production paths never did).
#[test]
fn harness_blake2b_isolated() {
    use zkpvm::chips::Blake2bCall;

    let mut side_note = SideNote::new(Vec::new(), Vec::new(), Vec::new());

    // One synthetic compression call.  Inputs are arbitrary — the
    // harness validates Blake2bChip's algebra (carry bounds, byte
    // permutations, V-state chain, output derivation), not the
    // specific output value.  Any well-formed (h, m, t, f) drives
    // the chip's full constraint surface.
    side_note.blake2b_calls.push(Blake2bCall {
        h: [0u64; 8],
        m: [0u64; 16],
        t: 0,
        f: true,
    });

    let config = PcsConfig {
        pow_bits: 5,
        fri_config: FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };

    let components: &[&'static dyn MachineProverComponent] = &[&chips::Blake2bChip];

    let proof = prove_with_explicit_components(&mut side_note, config, components)
        .expect("Blake2bChip harness: prove failed — chip-flatten regression \
                 (the OODS sanity check fired; degree ≥ 3 constraint slipped in)");

    let verifier_components: Vec<&dyn zkpvm::harness::MachineComponent> =
        components.iter().map(|c| *c as &dyn zkpvm::harness::MachineComponent).collect();

    let policy = PcsPolicy { min_pow_bits: 5, min_fri_queries: 3, min_fri_log_blowup: 0 };

    let verify_result = verify_with_explicit_components(
        proof, &side_note, &verifier_components, components, &policy,
    );

    // Expect open-chain rejection (lookups don't close without producer chips).
    use stwo::core::verifier::VerificationError;
    match verify_result {
        Err(VerificationError::InvalidStructure(msg))
            if msg.contains("claimed logup sum is not zero") => (),
        Err(e) => panic!("Blake2bChip harness: verify rejected for the wrong reason: {e:?}"),
        Ok(()) => panic!("Blake2bChip harness: verify accepted unexpectedly — \
                          something is balancing the lookups that shouldn't be"),
    }
}

/// CpuChip-isolated harness: prove `[&CpuChip]` alone with a real Add64
/// PVM step.  Validates that CpuChip's algebra (post Phase-I flatten)
/// is sound on the new Stwo pin.  Verify is open-chain — lookups don't
/// close without producer chips, but prove reaching SUCCESS means the
/// OODS sanity check passes (no constraint algebra regressions).
///
/// FIXED (commit after this): GateDivH padding-row fill — the helper
/// `(DivRemOp - 2)·(DivRemOp - 3)` has unconditional constraint, so
/// padding rows where DivRemOp=0 needed GateDivH = 6, not 0.
#[test]
fn harness_cpuchip_isolated_add64() {
    use javm::interpreter::Interpreter;
    use javm::instruction::Opcode;
    use javm::PVM_REGISTER_COUNT;
    use zkpvm::core::tracing::TracingPvm;
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 100;
    regs[1] = 200;
    let code = vec![Opcode::Add64 as u8, 0x10, 2, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    let pvm = Interpreter::new(
        code.clone(), bitmask.clone(), vec![], regs,
        vec![0u8; 4 * 1024 * 1024], 10_000, 25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);
    let steps = tracing.into_trace();

    let mut side_note = SideNote::new(steps, code, bitmask);
    let config = PcsConfig {
        pow_bits: 5,
        fri_config: FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };

    // Just CpuChip — if its flatten is OK, prove succeeds and verify
    // rejects on lookup imbalance.  If its flatten has a degree or
    // witness-fill bug, prove fails with ConstraintsNotSatisfied at
    // OODS sanity check.
    let components: &[&'static dyn MachineProverComponent] = &[&chips::CpuChip];

    prove_with_explicit_components(&mut side_note, config, components)
        .expect("CpuChip-only prove failed — chip flatten regression");
}

/// RistrettoChip-isolated harness — Session 2.1 follow-up of the perf
/// roadmap.  Prove `[&RistrettoChip]` alone with one
/// `ECALL_RISTRETTO_SCALAR_MULT` step (the canonical 2·G test).
///
/// Expected green state:
/// - prove SUCCEEDS (RistrettoChip's algebraic constraints all close
///   on its own columns; register-file lookups self-balance via the
///   chip's own producer/consumer rows).
/// - verify REJECTS open-chain because the chip emits per-byte
///   Range256 producer rows whose consumer (RangeMultiplicity256)
///   isn't in the slice.
///
/// What this validates:
/// - The `ScalarMultKind`/ECALL plumbing landed in `4efa343` doesn't
///   regress the existing chip-isolated proving path.
/// - Future fixed-base chip integration has a regression net: this
///   harness keeps passing every commit until the comb-method path is
///   wired in, at which point the test gets a sibling
///   `harness_ristretto_fixed_basepoint_isolated` covering the new
///   row class.
#[test]
fn harness_ristretto_isolated() {
    use javm::interpreter::Interpreter;
    use javm::instruction::Opcode;
    use javm::PVM_REGISTER_COUNT;
    use zkpvm::core::tracing::{TracingPvm, ECALL_RISTRETTO_SCALAR_MULT};

    // Lay out 32-byte buffers in flat_mem at known addresses.
    let scalar_addr: u64 = 0x1000;
    let point_addr: u64 = 0x1020;
    let output_addr: u64 = 0x1040;
    let mut flat_mem = vec![0u8; 0x2000];
    // scalar = 2
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[0] = 2;
    // Use a non-basepoint compressed point (`2 · G`) so the ECALL
    // handler classifies the record as `ScalarMultKind::Variable` and
    // drives RistrettoChip's variable-base ladder.  Step 8's routing
    // sends `FixedBasepoint` records onto the comb path, bypassing
    // RistrettoChip — using a fixed-base record here would leave
    // ristretto_field_rows empty and trivialize this harness.
    let two_g = curve25519_dalek::ristretto::RistrettoPoint::mul_base(
        &curve25519_dalek::scalar::Scalar::from(2u8),
    );
    let point_bytes: [u8; 32] = two_g.compress().to_bytes();
    flat_mem[scalar_addr as usize..scalar_addr as usize + 32].copy_from_slice(&scalar_bytes);
    flat_mem[point_addr as usize..point_addr as usize + 32].copy_from_slice(&point_bytes);

    // ecalli 200, then trap.  5-byte ecalli + 1-byte trap = 6 bytes.
    let imm = ECALL_RISTRETTO_SCALAR_MULT;
    let code = vec![
        Opcode::Ecalli as u8,
        (imm & 0xff) as u8,
        ((imm >> 8) & 0xff) as u8,
        ((imm >> 16) & 0xff) as u8,
        ((imm >> 24) & 0xff) as u8,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 1];

    let mut regs = [0u64; PVM_REGISTER_COUNT];
    // PVM φ[7] = A0 (RISC-V a0 / x10), φ[8] = A1, φ[9] = A2 — matches
    // grey-transpiler's `map_register` and the host handler's reads after
    // the φ[7/8/9] alignment fix in `tracing.rs`.
    regs[7] = scalar_addr;
    regs[8] = point_addr;
    regs[9] = output_addr;

    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, flat_mem, 10_000, 25);
    let mut tracing = TracingPvm::new(pvm);
    let _exit = tracing.run_with_precompiles();
    assert_eq!(tracing.ristretto_records.len(), 1);
    // Confirm the ECALL detector classified the non-basepoint correctly —
    // step 8's routing sends FixedBasepoint records onto the comb path,
    // so this harness uses Variable to keep exercising RistrettoChip.
    use zkpvm::core::tracing::ScalarMultKind;
    assert_eq!(tracing.ristretto_records[0].kind, ScalarMultKind::Variable);

    let ristretto_records = std::mem::take(&mut tracing.ristretto_records);
    let ristretto_mem_ops = std::mem::take(&mut tracing.ristretto_mem_ops);
    let steps = tracing.into_trace();

    let mut side_note = SideNote::new(steps, code, bitmask);
    side_note.ristretto_calls = ristretto_records;
    side_note.ristretto_mem_ops = ristretto_mem_ops;
    side_note.ingest_ristretto_boundary();

    let config = PcsConfig {
        pow_bits: 5,
        fri_config: FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };

    let components: &[&'static dyn MachineProverComponent] = &[&chips::RistrettoChip];

    let proof = prove_with_explicit_components(&mut side_note, config, components)
        .expect("RistrettoChip-only prove failed — chip-flatten or witness regression");

    let verifier_components: Vec<&dyn zkpvm::harness::MachineComponent> = components
        .iter()
        .map(|c| *c as &dyn zkpvm::harness::MachineComponent)
        .collect();
    let policy = PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    let verify_result = verify_with_explicit_components(
        proof,
        &side_note,
        &verifier_components,
        components,
        &policy,
    );
    use stwo::core::verifier::VerificationError;
    match verify_result {
        Err(VerificationError::InvalidStructure(msg))
            if msg.contains("claimed logup sum is not zero") => {}
        Err(e) => panic!("RistrettoChip harness: verify rejected for the wrong reason: {e:?}"),
        Ok(()) => panic!(
            "RistrettoChip harness: verify accepted unexpectedly — \
             something is balancing the lookups that shouldn't be"
        ),
    }
}

/// RistrettoCombTableChip-isolated harness — Session 2.1 step 3 of the
/// perf roadmap.  Validates the precomputed comb-table preprocessed
/// columns (1024 rows of `T[i][j] = j · 2^(4·i) · G`) and the
/// table-side lookup constraint emit cleanly under prove + verify.
///
/// All multiplicities default to zero — no consumer chip in scope yet
/// (Session 2.1 step 5+).  Lookup contribution is `-0 = 0` per row,
/// so the relation balance is trivially zero and verify accepts.
///
/// What this validates:
/// - Preprocessed-table fill: 1024 rows × 130 columns (window_idx,
///   scalar_window, x[32], y[32], z[32], t[32]) populated from
///   `comb_table::CombTable::from_base(ed25519_basepoint_extended())`
///   without panicking.
/// - The 130-limb relation constraint compiles and runs at degree ≤ 2.
/// - The chip's algebraic constraints (none today, only the relation)
///   close cleanly on the new Stwo pin.
#[test]
fn harness_ristretto_comb_table_isolated() {
    let mut side_note = SideNote::new(Vec::new(), Vec::new(), Vec::new());

    let config = PcsConfig {
        pow_bits: 5,
        fri_config: FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };

    let components: &[&'static dyn MachineProverComponent] = &[&chips::RistrettoCombTableChip];

    let proof = prove_with_explicit_components(&mut side_note, config, components)
        .expect("RistrettoCombTableChip-only prove failed — preprocessed-table fill regression");

    let verifier_components: Vec<&dyn zkpvm::harness::MachineComponent> = components
        .iter()
        .map(|c| *c as &dyn zkpvm::harness::MachineComponent)
        .collect();
    let policy = PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    verify_with_explicit_components(
        proof,
        &side_note,
        &verifier_components,
        components,
        &policy,
    )
    .expect("RistrettoCombTableChip-only verify failed — table closure regression");
}

/// Same chip but with a non-zero multiplicity injected on one row.
/// The chip emits a `-1` lookup contribution with no producer, so
/// verify must reject open-chain — same pattern as
/// `harness_blake2b_isolated`.
#[test]
fn harness_ristretto_comb_table_unbalanced_rejected() {
    let mut side_note = SideNote::new(Vec::new(), Vec::new(), Vec::new());
    // Bump multiplicity on row 0 (window_idx=0, scalar_window=0, which
    // is the identity entry).  Any single non-zero entry breaks balance.
    side_note.ristretto_comb_counts[0] = 1;

    let config = PcsConfig {
        pow_bits: 5,
        fri_config: FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };

    let components: &[&'static dyn MachineProverComponent] = &[&chips::RistrettoCombTableChip];

    let proof = prove_with_explicit_components(&mut side_note, config, components)
        .expect("RistrettoCombTableChip prove with mult=1 failed — algebra regression");

    let verifier_components: Vec<&dyn zkpvm::harness::MachineComponent> = components
        .iter()
        .map(|c| *c as &dyn zkpvm::harness::MachineComponent)
        .collect();
    let policy = PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    let verify_result = verify_with_explicit_components(
        proof,
        &side_note,
        &verifier_components,
        components,
        &policy,
    );
    use stwo::core::verifier::VerificationError;
    match verify_result {
        Err(VerificationError::InvalidStructure(msg))
            if msg.contains("claimed logup sum is not zero") => {}
        Err(e) => panic!("comb_table unbalanced harness: wrong rejection reason: {e:?}"),
        Ok(()) => panic!(
            "comb_table unbalanced harness: verify accepted unexpectedly — \
             relation closed despite no consumer in scope"
        ),
    }
}

/// Session 2.1 step 5 — comb-method lookup-balance harness.
///
/// Proves `[&RistrettoCombTableChip, &RistrettoFixedBaseConsumerChip,
/// &RistrettoCombAnchorChip, &RistrettoCombScalarBoundaryChip]`
/// together with one synthetic scalar.  The consumer emits +1 per
/// window (64 emissions); `populate_ristretto_comb_counts` matches
/// each emission with a +1 in the table chip's Multiplicity column;
/// the table chip's lookup contribution is −Multiplicity.
///
/// As of Session 2.1 step 8 (memory-binding), `RistrettoCombScalarBoundaryChip`
/// also emits a +IsReal `MemoryAccessLookupElements` producer per row to
/// pin the scalar bytes to PVM memory.  Since this harness does not
/// include `MemoryChip` / `MemoryBoundaryChip` in scope, that producer
/// goes unbalanced and verify rejects open-chain.  The fully-closed
/// chain is exercised in `harness_ristretto_fixed_base_e2e_with_memory`
/// below; this harness now serves as a regression net for the
/// comb→anchor→scalar-boundary→consumer chip algebra (PROVE must still
/// succeed; an algebra regression would surface as `ConstraintsNotSatisfied`).
///
/// What this validates:
/// - The 130-limb `RistrettoCombLookupElements` relation has no
///   constraint regressions on the producer + consumer sides.
/// - `populate_ristretto_comb_counts` correctly walks each call's
///   64 windows and bumps the table-chip multiplicity.
/// - The consumer chip's IsReal flag, padding behaviour, and column
///   layout coexist with the table chip's preprocessed table.
/// - Anchor + scalar-boundary chips' AIR algebra is degree ≤ 2 and
///   the per-row `ScalarByte = LowNibble + 16·HighNibble` constraint
///   holds across the synthesized witness.
#[test]
fn harness_ristretto_comb_balance() {
    use zkpvm::chips::{
        RistrettoCombAnchorChip, RistrettoCombScalarBoundaryChip, RistrettoCombTableChip,
        RistrettoFixedBaseConsumerChip,
    };
    use zkpvm::side_note::RistrettoCombCall;

    let mut side_note = SideNote::new(Vec::new(), Vec::new(), Vec::new());
    // One synthetic scalar.  Pick values that exercise both zero
    // nibbles and non-zero nibbles so the lookup table is hit at
    // multiple distinct rows (not just T[i][0] = identity).
    let mut scalar = [0u8; 32];
    for i in 0..32 {
        scalar[i] = (i as u8).wrapping_mul(11);
    }
    side_note.ristretto_comb_calls.push(RistrettoCombCall {
        scalar,
        out_bytes: [0u8; 32],
    });
    side_note.populate_ristretto_comb_counts();

    let config = PcsConfig {
        pow_bits: 5,
        fri_config: FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };

    let components: &[&'static dyn MachineProverComponent] = &[
        &RistrettoCombTableChip,
        &RistrettoCombAnchorChip,
        &RistrettoCombScalarBoundaryChip,
        &RistrettoFixedBaseConsumerChip,
    ];

    let proof = prove_with_explicit_components(&mut side_note, config, components)
        .expect("comb-balance harness: prove failed — relation or constraint regression");

    let verifier_components: Vec<&dyn zkpvm::harness::MachineComponent> = components
        .iter()
        .map(|c| *c as &dyn zkpvm::harness::MachineComponent)
        .collect();
    let policy = PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    let verify_result = verify_with_explicit_components(
        proof,
        &side_note,
        &verifier_components,
        components,
        &policy,
    );
    use stwo::core::verifier::VerificationError;
    match verify_result {
        Err(VerificationError::InvalidStructure(msg))
            if msg.contains("claimed logup sum is not zero") => {}
        Err(e) => panic!(
            "comb-balance harness: verify rejected for the wrong reason: {e:?}"
        ),
        Ok(()) => panic!(
            "comb-balance harness: verify accepted unexpectedly — \
             scalar-boundary chip's memory producer should be unbalanced \
             without MemoryChip in scope"
        ),
    }
}

/// Session 2.1 step 8 — fully-closed soundness chain for a synthesized
/// FixedBasepoint scalar mult call.  Drains every relation the chip
/// pair touches by including `MemoryChip` + `MemoryBoundaryChip` +
/// `RistrettoEcallChip` alongside the comb chips.
///
/// What this validates that `harness_ristretto_comb_balance` cannot:
/// - The scalar-boundary chip's `MemoryAccessLookupElements` producer
///   pairs cleanly with `MemoryChip`'s consumer for each scalar byte
///   address — no off-by-one or addr/ts witness divergence.
/// - The skip-scalar-bytes branch in `RistrettoEcallChip::collect_accesses`
///   keeps the ledger balanced (32 byte producers move from EcallChip
///   to ScalarBoundaryChip; total emissions per call unchanged).
/// - `MemoryBoundaryChip` injects matching initial-write tuples at
///   ts=0 for the scalar's first reads, drawing from
///   `side_note.initial_memory`.
#[test]
fn harness_ristretto_fixed_base_e2e_with_memory() {
    use zkpvm::chips::{
        MemoryBoundaryChip, MemoryChip, RistrettoCombAnchorChip,
        RistrettoCombScalarBoundaryChip, RistrettoCombTableChip, RistrettoEcallChip,
        RistrettoFixedBaseConsumerChip,
    };
    use zkpvm::core::tracing::{RistrettoMemOp, ScalarMultKind};
    use zkpvm::side_note::RistrettoCombCall;

    // Memory layout for the synthesized call.  Pick non-zero bytes
    // for the scalar so the comb chain hits non-identity table rows.
    let scalar_ptr: u32 = 0;
    let point_ptr: u32 = 64;
    let output_ptr: u32 = 128;
    let ts: u64 = 1;

    // Canonical scalar with non-zero bytes in the first half so the
    // comb chain hits non-identity table rows on the first ~16 windows
    // (rest stay at T[i][0] = identity).  Higher-order bytes stay zero
    // to keep the scalar within the curve25519 group order.
    let scalar_value = curve25519_dalek::scalar::Scalar::from(
        0x1234_5678_9abc_def0_u64,
    );
    let scalar = scalar_value.to_bytes();
    let basepoint =
        curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
    let out_bytes = (scalar_value
        * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT)
        .compress()
        .to_bytes();

    // initial_memory must contain the scalar + point bytes so
    // MemoryBoundaryChip's ts=0 producers carry the actor-observed
    // values (the prev_value chain in MemoryChip bottoms out at the
    // initial-memory byte).  Output region needs no initial value
    // since its first access is a write.
    let mut initial_memory = vec![0u8; 256];
    initial_memory[scalar_ptr as usize..scalar_ptr as usize + 32]
        .copy_from_slice(&scalar);
    initial_memory[point_ptr as usize..point_ptr as usize + 32]
        .copy_from_slice(&basepoint);

    let mut side_note = SideNote::new(Vec::new(), Vec::new(), Vec::new());
    side_note.initial_memory = initial_memory;
    side_note.ristretto_mem_ops.push(RistrettoMemOp {
        scalar_ptr,
        point_ptr,
        output_ptr,
        ts,
        scalar_bytes: scalar,
        point_bytes: basepoint,
        out_bytes,
        kind: ScalarMultKind::FixedBasepoint,
    });
    side_note
        .ristretto_comb_calls
        .push(RistrettoCombCall { scalar, out_bytes });
    side_note.populate_ristretto_comb_counts();

    let config = PcsConfig {
        pow_bits: 5,
        fri_config: FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };

    let components: &[&'static dyn MachineProverComponent] = &[
        &MemoryChip,
        &MemoryBoundaryChip,
        &RistrettoEcallChip,
        &RistrettoCombTableChip,
        &RistrettoCombAnchorChip,
        &RistrettoCombScalarBoundaryChip,
        &RistrettoFixedBaseConsumerChip,
    ];

    let proof = prove_with_explicit_components(&mut side_note, config, components)
        .expect(
            "fixed-base e2e harness: prove failed — chip algebra or witness regression",
        );

    let verifier_components: Vec<&dyn zkpvm::harness::MachineComponent> = components
        .iter()
        .map(|c| *c as &dyn zkpvm::harness::MachineComponent)
        .collect();
    let policy = PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    verify_with_explicit_components(
        proof,
        &side_note,
        &verifier_components,
        components,
        &policy,
    )
    .expect(
        "fixed-base e2e harness: verify failed — memory ledger or comb-chain \
         lookup balance regression",
    );
}

/// Session 2.1 step 8 — multi-call coverage for the comb chip pair.
///
/// Synthesizes 3 distinct FixedBasepoint scalar mult calls in one
/// trace, with three different scalars at three different memory
/// regions and timestamps.  Verifies that:
///   - `RistrettoCombScalarBoundaryChip`'s `CallIdx` column correctly
///     enumerates 0/1/2 across the 96 rows.
///   - The chip's parallel walk over `ristretto_comb_calls` and the
///     FixedBasepoint-filtered `ristretto_mem_ops` aligns each
///     scalar's bytes to the right `(scalar_ptr, ts)` pair.
///   - `RistrettoEcallChip` emits memory producers for point + output
///     bytes (96-32=64 per call) at the correct distinct addresses.
///   - `RistrettoCombAnchorChip`'s 64 ScalarWindow emissions per call
///     are balanced by 32 rows × 2 nibbles per call from the boundary
///     chip, across all 3 calls.
///
/// A regression in any per-call indexing (e.g., the boundary chip
/// reusing the wrong mem_op for a later call, or the anchor chip's
/// CallIdx fill being off-by-one) would surface as `claimed logup
/// sum is not zero` here.
#[test]
fn harness_ristretto_fixed_base_three_calls() {
    use zkpvm::chips::{
        MemoryBoundaryChip, MemoryChip, RistrettoCombAnchorChip,
        RistrettoCombScalarBoundaryChip, RistrettoCombTableChip, RistrettoEcallChip,
        RistrettoFixedBaseConsumerChip,
    };
    use zkpvm::core::tracing::{RistrettoMemOp, ScalarMultKind};
    use zkpvm::side_note::RistrettoCombCall;

    // Three calls with distinct scalars + non-overlapping memory regions.
    let calls: [(curve25519_dalek::scalar::Scalar, u32, u32, u32, u64); 3] = [
        (curve25519_dalek::scalar::Scalar::from(7u64), 0x000, 0x040, 0x080, 1),
        (
            curve25519_dalek::scalar::Scalar::from(0x1234_5678u64),
            0x100, 0x140, 0x180, 5,
        ),
        (
            curve25519_dalek::scalar::Scalar::from(0xdead_beef_cafe_babe_u64),
            0x200, 0x240, 0x280, 11,
        ),
    ];

    let basepoint =
        curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
    let mut initial_memory = vec![0u8; 1024];
    let mut side_note = SideNote::new(Vec::new(), Vec::new(), Vec::new());

    for &(scalar_value, scalar_ptr, point_ptr, output_ptr, ts) in &calls {
        let scalar = scalar_value.to_bytes();
        let out_bytes = (scalar_value
            * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        initial_memory[scalar_ptr as usize..scalar_ptr as usize + 32]
            .copy_from_slice(&scalar);
        initial_memory[point_ptr as usize..point_ptr as usize + 32]
            .copy_from_slice(&basepoint);
        side_note.ristretto_mem_ops.push(RistrettoMemOp {
            scalar_ptr,
            point_ptr,
            output_ptr,
            ts,
            scalar_bytes: scalar,
            point_bytes: basepoint,
            out_bytes,
            kind: ScalarMultKind::FixedBasepoint,
        });
        side_note
            .ristretto_comb_calls
            .push(RistrettoCombCall { scalar, out_bytes });
    }
    side_note.initial_memory = initial_memory;
    side_note.populate_ristretto_comb_counts();

    let config = PcsConfig {
        pow_bits: 5,
        fri_config: FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };

    let components: &[&'static dyn MachineProverComponent] = &[
        &MemoryChip,
        &MemoryBoundaryChip,
        &RistrettoEcallChip,
        &RistrettoCombTableChip,
        &RistrettoCombAnchorChip,
        &RistrettoCombScalarBoundaryChip,
        &RistrettoFixedBaseConsumerChip,
    ];

    let proof = prove_with_explicit_components(&mut side_note, config, components)
        .expect(
            "3-call harness: prove failed — likely a per-call indexing or \
             trace-fill misalignment regression",
        );

    let verifier_components: Vec<&dyn zkpvm::harness::MachineComponent> = components
        .iter()
        .map(|c| *c as &dyn zkpvm::harness::MachineComponent)
        .collect();
    let policy = PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    verify_with_explicit_components(
        proof,
        &side_note,
        &verifier_components,
        components,
        &policy,
    )
    .expect(
        "3-call harness: verify failed — comb-chain or memory ledger \
         imbalance under multi-call",
    );
}

/// Session 2.1 step 8 — soundness regression net for the scalar /
/// PVM-memory binding.  Synthesizes a call whose
/// `ristretto_comb_calls.scalar` (K1) and `ristretto_mem_ops.scalar_bytes`
/// (K2 ≠ K1) disagree byte-for-byte; the actor's PVM memory holds K2,
/// the comb chain consumes K1.  PROVE still succeeds (each chip's
/// witness is internally consistent for its own scalar), but VERIFY
/// must reject because:
///   - `RistrettoCombScalarBoundaryChip` emits memory producers at
///     `(Addr_i, K1[i], Ts, 0)`.
///   - `MemoryChip`'s consumer side, fed by `mem_op.scalar_bytes = K2`
///     and `initial_memory[scalar_ptr + i] = K2[i]`, holds tuples at
///     `(Addr_i, K2[i], Ts, 0)`.
///   - Tuples differ in the value limb, so the lookup balance is
///     non-zero and verify returns `claimed logup sum is not zero`.
///
/// Without this test, a future regression that broke the value-side
/// of the boundary tuple (e.g., emitted at the nibble byte_idx
/// instead of the call's scalar byte index) could leave the chain
/// looking balanced for any K1, making the binding cosmetic.
#[test]
fn harness_ristretto_scalar_memory_mismatch_rejected() {
    use zkpvm::chips::{
        MemoryBoundaryChip, MemoryChip, RistrettoCombAnchorChip,
        RistrettoCombScalarBoundaryChip, RistrettoCombTableChip, RistrettoEcallChip,
        RistrettoFixedBaseConsumerChip,
    };
    use zkpvm::core::tracing::{RistrettoMemOp, ScalarMultKind};
    use zkpvm::side_note::RistrettoCombCall;

    let scalar_ptr: u32 = 0;
    let point_ptr: u32 = 64;
    let output_ptr: u32 = 128;
    let ts: u64 = 1;

    // K1: what the boundary chip walks via ristretto_comb_calls.
    let k1_value = curve25519_dalek::scalar::Scalar::from(0x1234_5678_u64);
    let k1 = k1_value.to_bytes();
    // K2: what the actor's memory holds (≠ K1).
    let k2_value = curve25519_dalek::scalar::Scalar::from(0xdeadbeefu64);
    let k2 = k2_value.to_bytes();
    assert_ne!(k1, k2, "test setup: K1 must differ from K2 byte-wise");

    let basepoint =
        curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
    // out_bytes ties to K2 (actor's memory) for the EcallChip producer
    // side of the output write.
    let out_bytes = (k2_value
        * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT)
        .compress()
        .to_bytes();

    let mut initial_memory = vec![0u8; 256];
    initial_memory[scalar_ptr as usize..scalar_ptr as usize + 32]
        .copy_from_slice(&k2);
    initial_memory[point_ptr as usize..point_ptr as usize + 32]
        .copy_from_slice(&basepoint);

    let mut side_note = SideNote::new(Vec::new(), Vec::new(), Vec::new());
    side_note.initial_memory = initial_memory;
    side_note.ristretto_mem_ops.push(RistrettoMemOp {
        scalar_ptr,
        point_ptr,
        output_ptr,
        ts,
        scalar_bytes: k2,
        point_bytes: basepoint,
        out_bytes,
        kind: ScalarMultKind::FixedBasepoint,
    });
    // Mismatch: comb_calls says K1, mem_ops says K2.
    side_note
        .ristretto_comb_calls
        .push(RistrettoCombCall {
            scalar: k1,
            out_bytes,
        });
    side_note.populate_ristretto_comb_counts();

    let config = PcsConfig {
        pow_bits: 5,
        fri_config: FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };

    let components: &[&'static dyn MachineProverComponent] = &[
        &MemoryChip,
        &MemoryBoundaryChip,
        &RistrettoEcallChip,
        &RistrettoCombTableChip,
        &RistrettoCombAnchorChip,
        &RistrettoCombScalarBoundaryChip,
        &RistrettoFixedBaseConsumerChip,
    ];

    let proof = prove_with_explicit_components(&mut side_note, config, components)
        .expect(
            "scalar/memory mismatch harness: prove unexpectedly failed — \
             constraints should still satisfy individually; verify is the \
             gate that catches the lookup imbalance",
        );

    let verifier_components: Vec<&dyn zkpvm::harness::MachineComponent> = components
        .iter()
        .map(|c| *c as &dyn zkpvm::harness::MachineComponent)
        .collect();
    let policy = PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };
    let verify_result = verify_with_explicit_components(
        proof,
        &side_note,
        &verifier_components,
        components,
        &policy,
    );
    use stwo::core::verifier::VerificationError;
    match verify_result {
        Err(VerificationError::InvalidStructure(msg))
            if msg.contains("claimed logup sum is not zero") => {}
        Err(e) => panic!(
            "scalar/memory mismatch harness: verify rejected for the wrong \
             reason: {e:?}"
        ),
        Ok(()) => panic!(
            "scalar/memory mismatch harness: verify accepted unexpectedly — \
             scalar memory binding is structural only (regression)"
        ),
    }
}

/// Debug: ConsumerChip-isolated with EMPTY side_note (no calls).
/// All cells zero, all gates zero, no real emissions.  Should prove +
/// verify cleanly (open-chain trivially balanced at zero).  If this
/// panics the bug is structural; if it passes the bug is data-dependent.
#[test]
fn harness_ristretto_consumer_isolated_empty() {
    use zkpvm::chips::RistrettoFixedBaseConsumerChip;

    let mut side_note = SideNote::new(Vec::new(), Vec::new(), Vec::new());

    let config = PcsConfig {
        pow_bits: 5,
        fri_config: FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };

    let components: &[&'static dyn MachineProverComponent] =
        &[&RistrettoFixedBaseConsumerChip];

    let _proof = prove_with_explicit_components(&mut side_note, config, components)
        .expect("consumer-empty harness: prove failed");
}

/// CpuChip-isolated debug runner using Stwo's `AssertEvaluator`.
/// Pinpoints the failing constraint by row + constraint-#, replacing the
/// wave-by-wave bisection approach.  Requires the `debug-internals`
/// feature; run with:
///
///   cargo test -p zkpvm --features debug-internals --test chip_isolated \
///       harness_cpuchip_debug_add64 -- --ignored --nocapture
#[cfg(feature = "debug-internals")]
#[test]
#[ignore = "debug-only — pinpoints failing constraint when prove fails"]
fn harness_cpuchip_debug_add64() {
    use javm::interpreter::Interpreter;
    use javm::instruction::Opcode;
    use javm::PVM_REGISTER_COUNT;
    use zkpvm::core::tracing::TracingPvm;
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 100;
    regs[1] = 200;
    let code = vec![Opcode::Add64 as u8, 0x10, 2, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    let pvm = Interpreter::new(
        code.clone(), bitmask.clone(), vec![], regs,
        vec![0u8; 4 * 1024 * 1024], 10_000, 25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, javm::ExitReason::Trap);
    let steps = tracing.into_trace();

    let mut side_note = SideNote::new(steps, code, bitmask);
    let components: &[&'static dyn MachineProverComponent] = &[&chips::CpuChip];

    zkpvm::debug_assert_constraints_explicit(&mut side_note, components);
}
