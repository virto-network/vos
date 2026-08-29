#![cfg(feature = "prover")]

//! Mode::External voucher-proof pipeline smoke test.
//!
//! Loads `pvm/proof/fixtures/voucher-check`'s PVM ELF, traces a bare run
//! (no injected witness — the guest early-exits without proving),
//! proves it, then verifies via `vos_pvm_proof_verifier::verify_standalone`
//! against the program-commitment hash extracted from the proof.
//!
//! Pins:
//!   - A witness-less run is NOT a proving run: the guest returns
//!     early with a small trace and no io-hash binding.
//!   - The prove/verify pipeline accepts the resulting trace, and
//!     post-prove edits of the proof's boundary fields reject while
//!     `memory_commitment` stays unbound
//!     (`boundary_fields_are_tamper_evident`; the from-scratch-prover
//!     binding gate lives in `tests/boundary_binding.rs`).
//!   - The proof's program commitment is deterministic — a second prove
//!     of the same blob yields the same commitment, which is what
//!     `verify_standalone` checks against.
//!
//! Witness-driven behavior (io-hash reflects the public input, the
//! kernel re-execution reaches the precompiles) lives in the prover
//! extension's harness (`prove_transition.rs`), which builds real
//! succinct witnesses; the transition trace is segment-chain-sized,
//! far past what a smoke prove here could cover.
//!
//! Build the actor first:
//!     just build-voucher-check
//! Or directly:
//!     cd pvm/proof/fixtures/voucher-check && cargo +nightly build --release

use vos_pvm_proof::{
    SideNote, program_commitment_hex, program_commitment_of_proof, prove, prove_mobile,
};

const VOUCHER_CHECK_ELF: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/voucher-check/target/riscv64em-vos/release/voucher-check.elf",
);
const VOUCHER_CHECK_CATALOG: &str = include_str!("../fixtures/voucher-check/catalog.toml");
const VOUCHER_CHECK_PIN_ID: &str =
    "06482de863e4bfacc8255cb2d1154767442373f5a8d5b2cc9bdb8b6329e1dd5b";
const VOUCHER_CHECK_BLOB_HASH: &str =
    "5866fc11e48309aa97d87ce6c6c8469088a88c484a4f7fb9691c7c82fc50dd55";
const VOUCHER_CHECK_COMMITMENT: &str =
    "94eca0756b65f4727f91dca0306e8301615865410af2c45f03dd64c0334d3865";
const VOUCHER_CHECK_PROFILE: [u32; 32] = [
    15, 15, 16, 18, 9, 6, 4, 17, 4, 4, 4, 18, 12, 8, 8, 6, 8, 8, 8, 14, 13, 13, 12, 4, 7, 10, 11,
    6, 5, 6, 5, 16,
];
const VOUCHER_CHECK_IMAGE_ROOT: &str =
    "1ca7b5f557e618131b2c71840c0c95fe6115621de864011269393d5096185ec1";

fn load_voucher_check_catalog() -> vos::zk::ProvableCatalog {
    vos::zk::ProvableCatalog::from_toml_str(VOUCHER_CHECK_CATALOG)
        .expect("parse voucher-check catalog through the production API")
}

fn load_voucher_check_elf() -> Option<Vec<u8>> {
    match std::fs::read(VOUCHER_CHECK_ELF) {
        Ok(elf) => Some(elf),
        Err(_) => {
            eprintln!("SKIP: voucher-check ELF not built. Run:\n  just build-voucher-check");
            None
        }
    }
}

/// Load the voucher-check actor's ELF and transpile to a PVM blob.
/// Skips the test (prints SKIP and returns None) when the ELF is
/// missing, matching the convention used by `elf_integration.rs`.
fn load_voucher_check_blob() -> Option<Vec<u8>> {
    let elf = load_voucher_check_elf()?;
    Some(vos_pvm_compiler::link_elf(&elf).expect("transpile voucher-check ELF"))
}

/// Convenience around `vos_pvm_proof::actor::trace_blob` that panics on
/// parse failure — appropriate for tests where a missing CODE cap is
/// a bug in the fixture, not a runtime condition.
fn side_note_for_trace(blob: &[u8], gas: u64) -> SideNote {
    let side_note = vos_pvm_proof::actor::trace_blob(blob, gas).expect("trace voucher-check blob");
    eprintln!("Steps: {}", side_note.steps.len());
    side_note
}

/// Smoke test: voucher-check.elf traces cleanly under the PVM tracing
/// interpreter with NO injected witness. The guest must treat that as
/// "not a proving run" and return early — a small trace with no crypto
/// ECALLs, no panic. (The witness-driven path, where the kernel
/// re-execution reaches the precompiles, is covered by the prover
/// extension's `traced_io_hash_reflects_public_input`.)
#[test]
fn trace_voucher_check_bare_run() {
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let side_note = side_note_for_trace(&blob, 100_000_000);
    assert!(
        !side_note.steps.is_empty(),
        "bare run must still execute (decode + early exit)"
    );
    assert!(
        side_note.steps.len() < 100_000,
        "bare run must early-exit with a SMALL trace ({} steps) — a large \
         trace means the guest ran the kernel on garbage instead of \
         detecting the missing witness",
        side_note.steps.len()
    );
    assert!(
        side_note.ristretto_calls.is_empty(),
        "a witness-less run must not reach the crypto path"
    );
}

/// Full prove + verify_standalone round-trip over the bare-run trace.
#[test]
fn prove_verify_voucher_check_bare_run() {
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let mut side_note = side_note_for_trace(&blob, 100_000_000);
    let t = std::time::Instant::now();
    // mobile config (2× faster) so the smoke test stays sub-second to
    // sub-minute end-to-end.  Verify-standalone enforces a stricter
    // pcs_policy by default — pass MOBILE to allow mobile-config proofs.
    let proof = prove_mobile(&mut side_note).expect("prove voucher-check");
    eprintln!("Prove: {:.2?}", t.elapsed());

    let prog_hash = program_commitment_of_proof(&proof);
    eprintln!("Program commitment: {}", program_commitment_hex(&proof));

    let proof_bytes = bincode::serialize(&proof).expect("bincode serialize proof");
    eprintln!("Proof: {:.1} KB", proof_bytes.len() as f64 / 1024.0);

    let t = std::time::Instant::now();
    use vos_pvm_proof_verifier::{PcsPolicy, verify_standalone_with_pcs_policy};
    verify_standalone_with_pcs_policy(proof.clone(), prog_hash, &PcsPolicy::MOBILE)
        .expect("verify_standalone (MOBILE policy)");
    eprintln!("verify_standalone: {:?}", t.elapsed());

    // bincode round-trip — same path a Voucher.proof.bytes consumer
    // will follow on the receiving side.
    let proof_decoded: vos_pvm_proof::Proof =
        bincode::deserialize(&proof_bytes).expect("bincode deserialize");
    verify_standalone_with_pcs_policy(proof_decoded, prog_hash, &PcsPolicy::MOBILE)
        .expect("verify_standalone (after bincode roundtrip)");
}

/// Constraint-debug helper (feature `debug-internals`).  Pinpoints
/// which chip's row + constraint fails for the voucher-check trace.
/// Run with `cargo test -p vos-pvm-proof --features debug-internals --test
/// voucher_check_smoke debug_voucher_check_constraints -- --nocapture`
/// to get a `row #X, constraint #Y` panic from the first chip whose
/// assertions don't hold.
#[cfg(feature = "debug-internals")]
#[test]
fn debug_voucher_check_constraints() {
    use vos_pvm::instruction::Opcode;
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let mut side_note = side_note_for_trace(&blob, 100_000_000);
    let components = vos_pvm_proof::active_components(&side_note);
    eprintln!("Active components: {} of total chips", components.len());
    eprintln!(
        "SideNote counts: blake2b_calls={}, ristretto_calls={}, ristretto_comb_calls={}, ristretto_field_rows={}, scalar_binop_calls={}",
        side_note.blake2b_calls.len(),
        side_note.ristretto_calls.len(),
        side_note.ristretto_comb_calls.len(),
        side_note.ristretto_field_rows.len(),
        side_note.scalar_binop_calls.len(),
    );
    let mut se8_count = 0u32;
    let mut se16_count = 0u32;
    let mut ecall_count = 0u32;
    for s in &side_note.steps {
        match s.opcode {
            Opcode::SignExtend8 => se8_count += 1,
            Opcode::SignExtend16 => se16_count += 1,
            Opcode::Ecalli | Opcode::Ecall => ecall_count += 1,
            _ => {}
        }
    }
    eprintln!(
        "Opcode counts: SignExtend8={}, SignExtend16={}, Ecalli/Ecall={}",
        se8_count, se16_count, ecall_count
    );
    vos_pvm_proof::debug_assert_constraints_explicit(&mut side_note, &components);
}

/// Same as `debug_voucher_check_constraints` but forces all chips
/// into the component set (bypassing the activity filter). Lets us
/// test whether the constraint failure is due to a chip being dropped
/// that CpuChip still emits to (e.g. Blake2bChip being absent while
/// CpuChip still emits to blake2b_call_lookup with multiplicity 0).
#[cfg(feature = "debug-internals")]
#[test]
fn debug_voucher_check_constraints_all_chips() {
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let mut side_note = side_note_for_trace(&blob, 100_000_000);
    let components: Vec<_> = vos_pvm_proof::all_components().iter().copied().collect();
    eprintln!("Forced-all components: {}", components.len());
    vos_pvm_proof::debug_assert_constraints_explicit(&mut side_note, &components);
}

/// Program identity check: two independent prove calls over the same
/// blob yield the same program commitment.  This is the property
/// `clerk-prover`'s in-actor verifier will rely on — it bakes the
/// commitment as a constant and rejects proofs that don't match.
#[test]
fn voucher_check_program_commitment_is_deterministic() {
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let mut side_note_a = side_note_for_trace(&blob, 100_000_000);
    let proof_a = prove(&mut side_note_a).expect("prove A");
    let hash_a = program_commitment_of_proof(&proof_a);
    let mut side_note_b = side_note_for_trace(&blob, 100_000_000);
    let proof_b = prove(&mut side_note_b).expect("prove B");
    let hash_b = program_commitment_of_proof(&proof_b);
    assert_eq!(
        hash_a, hash_b,
        "two proofs of the same actor blob must commit to the same program hash"
    );
}

#[test]
fn voucher_check_catalog_is_a_valid_production_pin() {
    let catalog = load_voucher_check_catalog();
    assert_eq!(catalog.programs.len(), 1, "fixture must contain one pin");
    let pin = catalog
        .require_pin("voucher-check", VOUCHER_CHECK_PIN_ID)
        .expect("exact voucher-check pin");

    assert_eq!(pin.id, pin.content_id(), "pin identity must be canonical");
    assert_eq!(pin.blob_hash, VOUCHER_CHECK_BLOB_HASH);
    assert_eq!(pin.commitments, [VOUCHER_CHECK_COMMITMENT]);
    assert_eq!(pin.commitments_bytes().expect("commitment hex").len(), 1);
    assert_eq!(pin.allowlist_concat().expect("allowlist").len(), 32);
    assert_eq!(pin.canonical_profile, VOUCHER_CHECK_PROFILE);
    assert_eq!(pin.canonical_profile.len(), vos_pvm_proof::chip_idx::COUNT);
    assert_eq!(pin.seg_steps, 32_000);
    assert_eq!(pin.page_budget, 8);
    assert_eq!(pin.witness_addr, 699_776);
    assert_eq!(pin.unpatched_image_root, VOUCHER_CHECK_IMAGE_ROOT);
    pin.unpatched_image_root_bytes().expect("image-root hex");
}

#[test]
fn voucher_check_catalog_matches_built_artifact() {
    let Some(elf) = load_voucher_check_elf() else {
        return;
    };
    let blob = vos_pvm_compiler::link_elf(&elf).expect("transpile voucher-check ELF");
    let pin = load_voucher_check_catalog()
        .require_pin("voucher-check", VOUCHER_CHECK_PIN_ID)
        .expect("exact voucher-check pin")
        .clone();

    assert_eq!(
        vos::zk::bytes_to_hex(&vos::provable::task_blob_hash(&blob)),
        pin.blob_hash,
        "catalog blob_hash must name the transpiled fixture"
    );
    assert_eq!(
        vos::zk::witness_addr(&elf),
        Some(pin.witness_addr),
        "catalog witness address must match the ELF symbol"
    );

    let side_note = side_note_for_trace(&blob, 100_000_000);
    assert_eq!(
        vos::zk::bytes_to_hex(&vos_pvm_proof::page_merkle::image_root(
            &side_note.initial_memory
        )),
        pin.unpatched_image_root,
        "catalog image root must match the transpiled fixture"
    );
}

/// Release-maintenance gate for the checked-in canonical catalog. The
/// commitment depends only on the authenticated program/profile
/// preprocessed trace, so a bare execution is sufficient to re-measure it;
/// no production witness is needed. Kept ignored because the canonical proof
/// is intentionally heavyweight.
#[test]
#[ignore = "heavy canonical catalog re-measurement"]
fn voucher_check_catalog_commitment_matches_current_air() {
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let catalog = load_voucher_check_catalog();
    let pin = catalog
        .require_pin("voucher-check", VOUCHER_CHECK_PIN_ID)
        .expect("exact voucher-check pin");

    let side_note = side_note_for_trace(&blob, 100_000_000);
    let commitment =
        vos_pvm_proof::program_commitment_for_profile(&side_note, &pin.canonical_profile)
            .expect("measure catalog-shaped voucher-check commitment");
    let got = commitment.to_string();
    assert_eq!(
        pin.commitments,
        [got.clone()],
        "catalog commitment is stale; current AIR commitment is {got}"
    );
}

/// Tamper-evidence + binding test for `final_state.registers`:
/// flipping any byte of any register on a FINISHED proof must make
/// `verify_standalone` reject. Two mechanisms fire: the FS-transcript
/// mix (post-prove edits shift the verifier's challenges) and the
/// boundary-binding claimed-sum check (the edited metadata no longer
/// matches the committed closing-chip column).
///
/// SCOPE: this exercises POST-PROVE tampering only. It does NOT cover a
/// from-scratch prover who forges the closing read's COLUMN via the
/// register ledger's free `prev_value` — that column→trace gap is open
/// (see `chips/register_memory_closing.rs`), so the io-binding the
/// prover extension checks is sound against an honest prover but not yet
/// against a malicious one.
#[test]
fn final_state_registers_are_stark_bound() {
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let mut side_note = side_note_for_trace(&blob, 100_000_000);
    let proof = prove_mobile(&mut side_note).expect("prove voucher-check");
    let prog_hash = program_commitment_of_proof(&proof);

    // Sanity: pristine proof verifies.
    use vos_pvm_proof_verifier::{PcsPolicy, verify_standalone_with_pcs_policy};
    verify_standalone_with_pcs_policy(proof.clone(), prog_hash, &PcsPolicy::MOBILE)
        .expect("pristine proof must verify");

    // Tamper a single byte of register 0's claimed final value.
    let mut tampered = proof.clone();
    tampered.final_state.registers[0] ^= 1;
    let result = verify_standalone_with_pcs_policy(tampered, prog_hash, &PcsPolicy::MOBILE);
    assert!(
        result.is_err(),
        "tamper of final_state.registers[0] must make verify reject — \
         got {result:?}; if this passes, the closing chip isn't \
         actually constraining the field and the entire Phase Z0 \
         binding is decorative"
    );

    // Tamper a different register to make sure it isn't just one
    // privileged slot — the constraint must apply uniformly.
    let mut tampered_late = proof.clone();
    let last_idx = tampered_late.final_state.registers.len() - 1;
    tampered_late.final_state.registers[last_idx] ^= 0x80;
    let result_late =
        verify_standalone_with_pcs_policy(tampered_late, prog_hash, &PcsPolicy::MOBILE);
    assert!(
        result_late.is_err(),
        "tamper of final_state.registers[{last_idx}] must also make verify reject — \
         got {result_late:?}"
    );
}

/// ZK actor-IO ABI (halt-asm binding): the framework's
/// `halt_with_output_bound` places a 32-byte `vos::zk::compute_io_hash`
/// value into the final-state register window φ[9..12] as part of the
/// Gray Paper halt jump (the four hash words ride in `a2..a5` as inline-asm
/// `in` operands). The closing chip pins the final-register columns
/// and the boundary-binding check equates `final_state.registers` to
/// them, so the hash is read back by `Proof::public_io_hash` — no new
/// hostcall, no prover changes. (The column→trace link rests on the
/// register-ledger read-consistency, sound against an honest prover;
/// the from-scratch-prover gap is tracked in
/// `chips/register_memory_closing.rs`. These honest-prover tests are
/// unaffected.)
///
/// This pins the mechanism end-to-end at the vos-pvm-proof level: the binding is
/// non-zero (the actor really bound a hash), deterministic across
/// proves, and STARK-bound on every word of the φ[9..12] window
/// (tampering any of registers 9,10,11,12 makes verify reject).  The
/// exact value-match against a host-recomputed `compute_io_hash` is
/// exercised in the `prover` extension e2e: the binding is tagless, so
/// the verifier just recomputes `compute_io_hash(public_bytes,
/// return_bytes)` over the asserted I/O bytes — no shared actor/message
/// type is needed (the program commitment carries program identity).
#[test]
fn actor_io_hash_is_bound_and_nonzero() {
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    use vos_pvm_proof_verifier::{PcsPolicy, verify_standalone_with_pcs_policy};

    let mut side_note = side_note_for_trace(&blob, 100_000_000);
    let proof = prove_mobile(&mut side_note).expect("prove voucher-check");
    let prog_hash = program_commitment_of_proof(&proof);

    verify_standalone_with_pcs_policy(proof.clone(), prog_hash, &PcsPolicy::MOBILE)
        .expect("pristine proof must verify");

    // 1. The halt-binding actually populated the φ[9..12] window.
    let io_hash = proof.public_io_hash();
    assert_ne!(
        io_hash, [0u8; 32],
        "public_io_hash is the unbound [0u8;32] sentinel — the halt-asm \
         binding in run_refine_service did not land in φ[9..12]"
    );

    // 2. Determinism: a second prove of the same blob binds the same hash.
    let mut side_note2 = side_note_for_trace(&blob, 100_000_000);
    let proof2 = prove_mobile(&mut side_note2).expect("re-prove voucher-check");
    assert_eq!(
        io_hash,
        proof2.public_io_hash(),
        "io-hash binding must be deterministic across proves"
    );

    // 3. STARK-binding across the whole φ[9..12] window: tampering any of
    //    the four hash registers must make verify reject. (registers[12]
    //    is also covered by final_state_registers_are_stark_bound's
    //    last-index tamper; this pins all four uniformly as the io-hash.)
    for idx in 9..13 {
        let mut tampered = proof.clone();
        tampered.final_state.registers[idx] ^= 1;
        let result = verify_standalone_with_pcs_policy(tampered, prog_hash, &PcsPolicy::MOBILE);
        assert!(
            result.is_err(),
            "tamper of io-hash register φ[{idx}] must make verify reject — \
             got {result:?}; the binding is not actually STARK-bound"
        );
    }
}

/// Initial-state register binding, load-bearing:
/// `proof.initial_state.registers` is STARK-bound, symmetric to
/// `final_state.registers`. The boundary chip emits per-register tuples
/// at `ts = 0` sourced from `side_note.initial_regs`, and `prove()` makes
/// the proof field equal to that source. The FS-transcript mix ties the
/// metadata field to the verifier's challenge derivation; tampering shifts
/// lookup elements and breaks constraint satisfaction.
///
/// Binding only the final state would leave a `verify_chain` gap:
/// without binding both ends, an attacker could chain a segment N
/// proof (final_state bound) to a tampered segment N+1
/// (initial_state unbound metadata) and pass the chain check
/// while segment N+1's actual trace started from arbitrary registers.
#[test]
fn initial_state_registers_are_stark_bound() {
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let mut side_note = side_note_for_trace(&blob, 100_000_000);
    let proof = prove_mobile(&mut side_note).expect("prove voucher-check");
    let prog_hash = program_commitment_of_proof(&proof);

    use vos_pvm_proof_verifier::{PcsPolicy, verify_standalone_with_pcs_policy};
    verify_standalone_with_pcs_policy(proof.clone(), prog_hash, &PcsPolicy::MOBILE)
        .expect("pristine proof must verify");

    // Tamper a single byte of initial-state register 0.
    let mut tampered = proof.clone();
    tampered.initial_state.registers[0] ^= 1;
    let result = verify_standalone_with_pcs_policy(tampered, prog_hash, &PcsPolicy::MOBILE);
    assert!(
        result.is_err(),
        "tamper of initial_state.registers[0] must make verify reject — \
         got {result:?}; if this passes, Z0-init's binding is decorative \
         and verify_chain's safety in the initial direction is broken"
    );

    // Tamper the last register to confirm uniform coverage.
    let mut tampered_late = proof;
    let last_idx = tampered_late.initial_state.registers.len() - 1;
    tampered_late.initial_state.registers[last_idx] ^= 0x80;
    let result_late =
        verify_standalone_with_pcs_policy(tampered_late, prog_hash, &PcsPolicy::MOBILE);
    assert!(
        result_late.is_err(),
        "tamper of initial_state.registers[{last_idx}] must also make verify reject — \
         got {result_late:?}"
    );
}

/// `verify_standalone` must reject any proof with
/// `component_mask = 0` at the current `format_version`. The mask-zero
/// sentinel is the chip-isolated `prove_with_explicit_components` marker,
/// and chip-isolated proofs deliberately skip the FS-transcript mix of
/// `final_state.registers` on the prover side. Without this reject, an
/// attacker could ship a chip-isolated proof (no prover-side mix) to
/// `verify_standalone` and tamper the metadata field unobserved —
/// bypassing the entire register binding.
#[test]
fn verify_standalone_rejects_mask_zero() {
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let mut side_note = side_note_for_trace(&blob, 100_000_000);
    let proof = prove_mobile(&mut side_note).expect("prove voucher-check");
    let prog_hash = program_commitment_of_proof(&proof);

    use vos_pvm_proof_verifier::{PcsPolicy, verify_standalone_with_pcs_policy};
    // Sanity: pristine proof verifies (mask is non-zero on the default path).
    verify_standalone_with_pcs_policy(proof.clone(), prog_hash, &PcsPolicy::MOBILE)
        .expect("pristine proof must verify");

    // Tamper: zero the component_mask. Emulates a chip-isolated proof
    // being fed to verify_standalone.
    let mut tampered = proof;
    tampered.component_mask = 0;
    let result = verify_standalone_with_pcs_policy(tampered, prog_hash, &PcsPolicy::MOBILE);
    assert!(
        matches!(result, Err(ref e) if format!("{e:?}").contains("component_mask = 0")),
        "verify_standalone must reject component_mask = 0 with a specific error — \
         got {result:?}; if this passes, the chip-isolated → standalone bypass \
         documented in the Z0 follow-up is open"
    );
}

/// Boundary-field tamper-evidence: registers, pc and timestamp on both
/// `proof.initial_state` and `proof.final_state` are FS-mixed, so editing
/// any of them on a FINISHED proof shifts the verifier's challenges and
/// the proof rejects — this test exercises exactly that post-prove
/// edit. (Such edits ALSO fail the boundary-binding claimed-sum check;
/// the from-scratch prover that mixes a lie from the start is covered by
/// `tests/boundary_binding.rs`.) `memory_commitment` is neither mixed nor
/// bound, so editing it still verifies.
#[test]
fn boundary_fields_are_tamper_evident() {
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let mut side_note = side_note_for_trace(&blob, 100_000_000);
    let proof = prove_mobile(&mut side_note).expect("prove voucher-check");
    let prog_hash = program_commitment_of_proof(&proof);

    use vos_pvm_proof_verifier::{PcsPolicy, verify_standalone_with_pcs_policy};

    // pc — tamper-evident on both ends (v4).
    let mut tampered_pc = proof.clone();
    tampered_pc.final_state.pc ^= 0x1000;
    assert!(
        verify_standalone_with_pcs_policy(tampered_pc, prog_hash, &PcsPolicy::MOBILE).is_err(),
        "v4 mixes final_state.pc — editing a finished proof must reject"
    );
    let mut tampered_initial_pc = proof.clone();
    tampered_initial_pc.initial_state.pc ^= 0x1000;
    assert!(
        verify_standalone_with_pcs_policy(tampered_initial_pc, prog_hash, &PcsPolicy::MOBILE)
            .is_err(),
        "v4 mixes initial_state.pc — editing a finished proof must reject"
    );

    // timestamp — tamper-evident on both ends (v4).
    let mut tampered_ts = proof.clone();
    tampered_ts.final_state.timestamp ^= 1;
    assert!(
        verify_standalone_with_pcs_policy(tampered_ts, prog_hash, &PcsPolicy::MOBILE).is_err(),
        "v4 mixes final_state.timestamp — editing a finished proof must reject"
    );
    let mut tampered_initial_ts = proof.clone();
    tampered_initial_ts.initial_state.timestamp ^= 1;
    assert!(
        verify_standalone_with_pcs_policy(tampered_initial_ts, prog_hash, &PcsPolicy::MOBILE)
            .is_err(),
        "v4 mixes initial_state.timestamp — editing a finished proof must reject"
    );

    // memory_commitment — still unbound metadata on both ends.
    let mut tampered_mem = proof.clone();
    tampered_mem.final_state.memory_commitment[0] ^= 0xff;
    verify_standalone_with_pcs_policy(tampered_mem, prog_hash, &PcsPolicy::MOBILE).expect(
        "memory_commitment is not circuit-derived — tamper must still verify. \
         If this fails, a memory-ledger closing landed; update the scope doc.",
    );
    let mut tampered_initial_mem = proof;
    tampered_initial_mem.initial_state.memory_commitment[0] ^= 0xff;
    verify_standalone_with_pcs_policy(tampered_initial_mem, prog_hash, &PcsPolicy::MOBILE).expect(
        "initial_state.memory_commitment is not circuit-derived — tamper must still verify.",
    );
}
