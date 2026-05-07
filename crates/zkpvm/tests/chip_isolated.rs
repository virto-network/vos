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
