#![cfg(feature = "prover")]

//! Chip-isolated prove/verify harness smoke tests.
//!
//! These tests validate `prove_with_explicit_components` /
//! `verify_with_explicit_components`: prove each chip's AIR in isolation
//! and check the expected accept (self-balancing lookups) or open-chain
//! reject (producer with no consumer in scope).
//!
//! The smoke test below uses only bound-1 chips (already at degree ≤ 2)
//! on the lifted protocol.  If it fails, the harness wiring itself is
//! broken and no chip-isolated validation can proceed.

use vos_pvm_proof::{
    FriConfig, PcsConfig, PcsPolicy, SideNote, chips, harness::MachineProverComponent,
    prove_with_explicit_components, verify_with_explicit_components,
};

/// Minimal bound-1-only configuration.  These chips all declare
/// `LOG_CONSTRAINT_DEGREE_BOUND = 1` (default) so they work on the v2.x
/// lifted protocol without any rewrites.
///
/// Picked for: simple boundary semantics, no cross-chip lookup
/// dependencies that need closure with an empty side_note.
const BOUND1_HARNESS_COMPONENTS: &[&'static dyn MachineProverComponent] =
    &[&chips::RangeMultiplicity256];

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
/// - Stwo accepts a bound-1 AIR cleanly.
///
/// What this does NOT validate:
/// - High-bound chip flattening (Blake2b/Mul/DivRem/Cpu are
///   covered by their own isolated harnesses).
/// - Lookup balance closure across chips (that needs sink components —
///   out of scope for this smoke test).
#[test]
fn harness_smoke_bound1_only() {
    let mut side_note = SideNote::new(Vec::new(), Vec::new(), Vec::new());

    // Minimal valid PcsConfig — fast prove for a smoke test.
    let config = PcsConfig {
        pow_bits: 5,
        fri_config: FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
        deep_batching: Default::default(),
    };

    let proof = prove_with_explicit_components(&mut side_note, config, BOUND1_HARNESS_COMPONENTS)
        .expect("harness smoke: prove failed on bound-1 AIR — wiring bug");

    // Build the verifier-trait slice via upcast.
    let verifier_components: Vec<&dyn vos_pvm_proof::harness::MachineComponent> =
        BOUND1_HARNESS_COMPONENTS
            .iter()
            .map(|c| *c as &dyn vos_pvm_proof::harness::MachineComponent)
            .collect();

    // Cheap policy matching the cheap PcsConfig — production verify
    // would use PcsPolicy::STANDARD; the harness accepts its own cheap
    // config to keep chip-isolated validation cycles fast.
    let policy = PcsPolicy {
        min_pow_bits: 5,
        min_fri_queries: 3,
        min_fri_log_blowup: 0,
    };

    verify_with_explicit_components(
        proof,
        &side_note,
        &verifier_components,
        BOUND1_HARNESS_COMPONENTS,
        &policy,
    )
    .expect("harness smoke: verify failed on bound-1 AIR — wiring bug");
}

/// Blake2bChip-isolated harness.  Asserts:
///
/// - `prove_with_explicit_components([&Blake2bChip], ...)` SUCCEEDS
///   (the chip's algebraic constraints are all degree ≤ 2).
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
///   validation (lookup tuple correctness, which the full-system
///   integration tests already cover).
/// - The full-system path (`prove_add64`) checks lookup correctness
///   end-to-end.
///
/// An upstream Stwo bug — `MerkleProverLifted::decommit` index OOB on
/// mixed-width column traces — is documented in
/// `STWO_MERKLE_LIFTED_OOB_ISSUE_DRAFT.md` (not blocking: bound-1 chips
/// and this harness shape don't trip it, and production paths never
/// did).
#[test]
fn harness_blake2b_isolated() {
    use vos_pvm_proof::chips::Blake2bCall;

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
        deep_batching: Default::default(),
    };

    let components: &[&'static dyn MachineProverComponent] = &[&chips::Blake2bChip];

    let proof = prove_with_explicit_components(&mut side_note, config, components).expect(
        "Blake2bChip harness: prove failed — chip-flatten regression \
                 (the OODS sanity check fired; degree ≥ 3 constraint slipped in)",
    );

    let verifier_components: Vec<&dyn vos_pvm_proof::harness::MachineComponent> = components
        .iter()
        .map(|c| *c as &dyn vos_pvm_proof::harness::MachineComponent)
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

    // Expect open-chain rejection (lookups don't close without producer chips).
    use stwo::core::verifier::VerificationError;
    match verify_result {
        Err(VerificationError::InvalidStructure(msg))
            if msg.contains("claimed logup sum is not zero") => {}
        Err(e) => panic!("Blake2bChip harness: verify rejected for the wrong reason: {e:?}"),
        Ok(()) => panic!(
            "Blake2bChip harness: verify accepted unexpectedly — \
                          something is balancing the lookups that shouldn't be"
        ),
    }
}

/// Blake2bBoundaryChip-isolated harness.  The boundary chip reuses the
/// shared compression core over a distinct `"blake2bnd"` preprocessed
/// prefix and adds its own IsReal anchor + Blake2bCompression producer.
/// This validates its algebra (anchor + production at row 95 + the schedule
/// fill under the distinct prefix) reaches a clean prove, then expects the
/// open-chain rejection at verify (the Blake2bCompression productions and
/// the BitwiseAnd / Range256 consumers have no balancing chips in scope —
/// `MemoryPageChip` / `MemoryMerkleChip` are not included here).
#[test]
fn harness_blake2b_boundary_isolated() {
    use vos_pvm_proof::chips::Blake2bCall;

    let mut side_note = SideNote::new(Vec::new(), Vec::new(), Vec::new());

    // One synthetic Merkle compression — arbitrary (h, m, t, f); the harness
    // validates the boundary chip's algebra, not the specific hash value.
    side_note.merkle_blake2b_calls.push(Blake2bCall {
        h: [0u64; 8],
        m: [0u64; 16],
        t: 0,
        f: true,
    });

    let config = PcsConfig {
        pow_bits: 5,
        fri_config: FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
        deep_batching: Default::default(),
    };

    let components: &[&'static dyn MachineProverComponent] = &[&chips::Blake2bBoundaryChip];

    let proof = prove_with_explicit_components(&mut side_note, config, components).expect(
        "Blake2bBoundaryChip harness: prove failed — IsReal anchor / production / \
         shared-core-under-distinct-prefix regression (OODS sanity check fired)",
    );

    let verifier_components: Vec<&dyn vos_pvm_proof::harness::MachineComponent> = components
        .iter()
        .map(|c| *c as &dyn vos_pvm_proof::harness::MachineComponent)
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
        Err(e) => {
            panic!("Blake2bBoundaryChip harness: verify rejected for the wrong reason: {e:?}")
        }
        Ok(()) => panic!(
            "Blake2bBoundaryChip harness: verify accepted unexpectedly — \
             something is balancing the lookups that shouldn't be"
        ),
    }
}

/// CpuChip-isolated harness: prove `[&CpuChip]` alone with a real Add64
/// PVM step.  Validates that CpuChip's algebra is sound.  Verify is
/// open-chain — lookups don't close without producer chips, but prove
/// reaching SUCCESS means the OODS sanity check passes (no constraint
/// algebra regressions).
///
/// Note on GateDivH padding-row fill: the helper
/// `(DivRemOp - 2)·(DivRemOp - 3)` is unconditionally constrained, so
/// padding rows where DivRemOp=0 require GateDivH = 6, not 0.
#[test]
fn harness_cpuchip_isolated_add64() {
    use vos_pvm::PVM_REGISTER_COUNT;
    use vos_pvm::instruction::Opcode;
    use vos_pvm::interpreter::Interpreter;
    use vos_pvm_proof::core::tracing::TracingPvm;
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 100;
    regs[1] = 200;
    let code = vec![Opcode::Add64 as u8, 0x10, 2, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10_000,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, vos_pvm::ExitReason::Panic);
    let steps = tracing.into_trace();

    let mut side_note = SideNote::new(steps, code, bitmask);
    let config = PcsConfig {
        pow_bits: 5,
        fri_config: FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
        deep_batching: Default::default(),
    };

    // Just CpuChip — if its flatten is OK, prove succeeds and verify
    // rejects on lookup imbalance.  If its flatten has a degree or
    // witness-fill bug, prove fails with ConstraintsNotSatisfied at
    // OODS sanity check.
    let components: &[&'static dyn MachineProverComponent] = &[&chips::CpuChip];

    prove_with_explicit_components(&mut side_note, config, components)
        .expect("CpuChip-only prove failed — chip flatten regression");
}

/// An honest `add64` row satisfies every CpuChip constraint, checked with
/// Stwo's `AssertEvaluator`, which names the failing row and constraint.
#[cfg(feature = "debug-internals")]
#[test]
fn cpuchip_constraints_hold_for_add64() {
    use vos_pvm::PVM_REGISTER_COUNT;
    use vos_pvm::instruction::Opcode;
    use vos_pvm::interpreter::Interpreter;
    use vos_pvm_proof::core::tracing::TracingPvm;
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 100;
    regs[1] = 200;
    let code = vec![Opcode::Add64 as u8, 0x10, 2, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 4 * 1024 * 1024],
        10_000,
    );
    let mut tracing = TracingPvm::new(pvm);
    let exit = tracing.run();
    assert_eq!(exit, vos_pvm::ExitReason::Panic);
    let steps = tracing.into_trace();

    let mut side_note = SideNote::new(steps, code, bitmask);
    let components: &[&'static dyn MachineProverComponent] = &[&chips::CpuChip];

    vos_pvm_proof::debug_assert_constraints_explicit(&mut side_note, components);
}
