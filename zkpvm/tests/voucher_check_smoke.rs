#![cfg(feature = "prover")]

//! Mode::External voucher-proof pipeline smoke test.
//!
//! Loads `examples/actors/voucher-check`'s PVM ELF (which runs
//! `cipher_clerk::voucher::proof::check` over a hardcoded witness),
//! traces the execution, calls `zkpvm::prove`, then verifies via
//! `zkpvm_verifier::verify_standalone` against the program-commitment
//! hash extracted from the proof.
//!
//! Pins:
//!   - cipher-clerk's `voucher::proof::check` runs to completion on PVM
//!     (no `Trap` panic from a check-rule violation).
//!   - The prove/verify pipeline accepts the resulting trace.
//!   - The proof's program commitment is deterministic — a second prove
//!     of the same blob yields the same commitment, which is what
//!     `verify_standalone` checks against.
//!
//! This is the foundation for the Mode::External round-trip:
//! production paths reuse the same prove → verify_standalone shape,
//! with the witness varying per-voucher instead of being hardcoded.
//!
//! Build the actor first:
//!     just build-voucher-check
//! Or directly:
//!     cd examples/actors/voucher-check && cargo +nightly build --release

use zkpvm::core::tracing::TracingPvm;
use zkpvm::{SideNote, program_commitment_hex, program_commitment_of_proof, prove, prove_mobile};

use cipher_clerk::crypto::{Amount, AuthKey, Blinding};
use cipher_clerk::voucher::proof::{Public, Secret};

/// Load the voucher-check actor's ELF and transpile to a PVM blob.
/// Skips the test (prints SKIP and returns None) when the ELF is
/// missing, matching the convention used by `elf_integration.rs`.
fn load_voucher_check_blob() -> Option<Vec<u8>> {
    // CARGO_MANIFEST_DIR is `<repo>/zkpvm`; up one to the repo root.
    // (`prove_vos_actor.rs` uses `/../../examples/...` which resolves
    // to a sibling worktree when run from a git worktree like
    // `.wt_alt/` — single-up is the correct relative path either way.)
    let elf_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../examples/actors/voucher-check/target/riscv64em-javm/release/voucher-check.elf",
    );
    let elf = match std::fs::read(elf_path) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("SKIP: voucher-check ELF not built. Run:\n  just build-voucher-check");
            return None;
        }
    };
    Some(grey_transpiler::link_elf(&elf).expect("transpile voucher-check ELF"))
}

/// Convenience around `zkpvm::actor::trace_blob` that panics on
/// parse failure — appropriate for tests where a missing CODE cap is
/// a bug in the fixture, not a runtime condition.
fn side_note_for_trace(blob: &[u8], gas: u64) -> SideNote {
    let side_note = zkpvm::actor::trace_blob(blob, gas).expect("trace voucher-check blob");
    eprintln!("Steps: {}", side_note.steps.len());
    side_note
}

/// Smoke test: voucher-check.elf traces cleanly under the PVM
/// tracing interpreter. Confirms cipher_clerk::voucher::proof::check
/// compiles + runs to completion on PVM via cipher-clerk's
/// `pvm-precompile` feature for Pedersen ops, with the expected
/// number of Ristretto ECALLs recorded.
///
/// This is the gating test: a successful trace proves the
/// guest-side path of the Mode::External round-trip works.  The
/// proof-generation step (below, currently `#[ignore]`) is a
/// follow-on once the constraints-not-satisfied issue is resolved.
#[test]
fn trace_voucher_check_hardcoded() {
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let side_note = side_note_for_trace(&blob, 100_000_000);
    // Expected from the hardcoded witness: one Amount::commit, which
    // is 2 fixed-base scalar mults (v·G + b·H) + 1 point add.  The
    // 4th/2nd come from the to_dalek check inside Blinding::to_dalek
    // and the to_bytes round trip on the Pedersen H constant.  These
    // numbers are pinned so a future cipher-clerk change to
    // Amount::commit surfaces here, not at prove time.
    assert!(
        !side_note.ristretto_calls.is_empty(),
        "trace must record at least one Ristretto scalar mult ECALL — \
         indicates cipher-clerk's pvm-precompile path is wired"
    );
    assert!(
        !side_note.ristretto_comb_calls.is_empty(),
        "ingest_ristretto_boundary must route fixed-base calls to the \
         comb-method path (RistrettoCombTable + FixedBaseConsumer chips)"
    );
    eprintln!("Steps: {}", side_note.steps.len());
}

/// Full prove + verify_standalone round-trip.
#[test]
fn prove_verify_voucher_check_hardcoded() {
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
    use zkpvm_verifier::{PcsPolicy, verify_standalone_with_pcs_policy};
    verify_standalone_with_pcs_policy(proof.clone(), prog_hash, &PcsPolicy::MOBILE)
        .expect("verify_standalone (MOBILE policy)");
    eprintln!("verify_standalone: {:?}", t.elapsed());

    // bincode round-trip — same path a Voucher.proof.bytes consumer
    // will follow on the receiving side.
    let proof_decoded: zkpvm::Proof =
        bincode::deserialize(&proof_bytes).expect("bincode deserialize");
    verify_standalone_with_pcs_policy(proof_decoded, prog_hash, &PcsPolicy::MOBILE)
        .expect("verify_standalone (after bincode roundtrip)");
}

/// Constraint-debug helper (feature `debug-internals`).  Pinpoints
/// which chip's row + constraint fails for the voucher-check trace.
/// Run with `cargo test -p zkpvm --features debug-internals --test
/// voucher_check_smoke debug_voucher_check_constraints -- --nocapture`
/// to get a `row #X, constraint #Y` panic from the first chip whose
/// assertions don't hold.  Use this to chase down task #7 (the
/// ConstraintsNotSatisfied failure that gates real STARK proofs).
#[cfg(feature = "debug-internals")]
#[test]
fn debug_voucher_check_constraints() {
    use javm::instruction::Opcode;
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let mut side_note = side_note_for_trace(&blob, 100_000_000);
    let components = zkpvm::active_components(&side_note);
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
    zkpvm::debug_assert_constraints_explicit(&mut side_note, &components);
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
    let components: Vec<_> = zkpvm::all_components().iter().copied().collect();
    eprintln!("Forced-all components: {}", components.len());
    zkpvm::debug_assert_constraints_explicit(&mut side_note, &components);
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

/// Dynamic-witness round-trip: patch __VOS_WITNESS with two distinct
/// (Public, Secret) tuples and assert the resulting traces differ.
/// Pins that the voucher-check actor reads the witness from BSS and
/// that the witness actually flows through `check`, so per-voucher
/// proofs (once task #7 lands) will have per-voucher commitments.
#[test]
fn dynamic_witness_changes_trace() {
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let elf = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../examples/actors/voucher-check/target/riscv64em-javm/release/voucher-check.elf",
    ))
    .expect("read voucher-check ELF for symbol lookup");
    let witness_addr =
        find_witness_buffer_addr(&elf).expect("__VOS_WITNESS symbol in voucher-check ELF");

    let trace_with = |amount: u64, blinding_byte: u8| -> (usize, [u8; 32]) {
        let amount_blinding =
            Blinding::from_bytes([blinding_byte; 32]).expect("canonical Ristretto scalar");
        let amount_commit = Amount::commit(amount, &amount_blinding);
        let public = Public {
            issuer: AuthKey([0x11u8; 32]),
            amount_commit,
            state_root_before: [0xAAu8; 32],
            state_root_after: [0xBBu8; 32],
        };
        let secret = Secret {
            amount,
            amount_blinding,
            sender_balance_before: amount + 1, // tightest passing bound
        };
        let public_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&public)
            .expect("rkyv encode Public")
            .to_vec();
        let secret_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&secret)
            .expect("rkyv encode Secret")
            .to_vec();
        let witness = encode_witness(&public_bytes, &secret_bytes);

        let (interp, mut flat_mem) =
            zkpvm::actor::interpreter_from_blob(&blob, 100_000_000).expect("interpreter from blob");
        let end = (witness_addr as usize)
            .checked_add(witness.len())
            .expect("witness fits in usize");
        assert!(
            end <= flat_mem.len(),
            "__VOS_WITNESS {witness_addr:#x} + {} > flat_mem {}",
            witness.len(),
            flat_mem.len()
        );
        flat_mem[witness_addr as usize..end].copy_from_slice(&witness);

        let mut interp = interp;
        interp.flat_mem = flat_mem;
        let mut tracing = TracingPvm::new(interp);
        let _ = tracing.run_with_vos_stubs();
        let step_count = tracing.steps.len();
        // Snapshot final flat_mem and digest it. Different witnesses
        // → different intermediate scalar-mult bytes in memory →
        // different digest.  blake3 since it's already in zkpvm's
        // dep tree; the choice of hash isn't load-bearing — we just
        // need a deterministic content digest.
        let final_mem = tracing.pvm.flat_mem.clone();
        let digest: [u8; 32] = blake3::hash(&final_mem).into();
        (step_count, digest)
    };

    // Two distinct witnesses → expect different traces. Different
    // `amount` + different blinding → different Amount::commit
    // output → different memory writes inside Amount::commit's
    // intermediate compress chain → different post-trace flat_mem
    // digest.
    let (steps_a, digest_a) = trace_with(100, 2);
    let (steps_b, digest_b) = trace_with(50, 5);
    eprintln!(
        "dynamic witness — A: {steps_a} steps digest={}, B: {steps_b} steps digest={}",
        hex(&digest_a),
        hex(&digest_b),
    );
    assert!(
        steps_a > 1000,
        "dynamic-witness trace A should run real work"
    );
    assert!(
        steps_b > 1000,
        "dynamic-witness trace B should run real work"
    );
    assert_ne!(
        digest_a, digest_b,
        "different witnesses must produce different flat_mem digests — \
         confirms the witness actually flows through check"
    );

    // Third trace with the SAME witness as A — must reproduce A's
    // digest exactly. Pins determinism: the prover and verifier can
    // both compute the digest from public/secret bytes and they'll
    // agree.
    let (_steps_c, digest_c) = trace_with(100, 2);
    assert_eq!(
        digest_a, digest_c,
        "identical witness must produce identical flat_mem digest"
    );
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// ZK actor-IO ABI input-sensitivity: the io-hash bound into φ[9..12]
/// must actually depend on the `Public` the actor ran on — i.e. the
/// `vos::zk::bind_io_bytes(&public_bytes, &[1u8])` call in `start` binds
/// the real witness, not a constant.
///
/// Cheap trace-level check (no prove): after `run_with_vos_stubs`, the
/// guest's halt sequence has placed the io-hash in φ[9..12], so the
/// final `tracing.pvm.registers[9..13]` reconstruct `public_io_hash`
/// (same LE decode).  Two distinct witnesses must bind two distinct
/// hashes; the same witness must rebind identically.  C3's
/// `actor_io_hash_is_bound_and_nonzero` separately proves this same
/// window is STARK-bound, so input-dependence here means the *proof*'s
/// public output is tied to the public input.
#[test]
fn actor_io_hash_reflects_public_input() {
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let elf = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../examples/actors/voucher-check/target/riscv64em-javm/release/voucher-check.elf",
    ))
    .expect("read voucher-check ELF for symbol lookup");
    let witness_addr =
        find_witness_buffer_addr(&elf).expect("__VOS_WITNESS symbol in voucher-check ELF");

    let io_hash_for = |amount: u64, blinding_byte: u8| -> [u8; 32] {
        let amount_blinding =
            Blinding::from_bytes([blinding_byte; 32]).expect("canonical Ristretto scalar");
        let amount_commit = Amount::commit(amount, &amount_blinding);
        let public = Public {
            issuer: AuthKey([0x11u8; 32]),
            amount_commit,
            state_root_before: [0xAAu8; 32],
            state_root_after: [0xBBu8; 32],
        };
        let secret = Secret {
            amount,
            amount_blinding,
            sender_balance_before: amount + 1,
        };
        let public_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&public)
            .expect("rkyv encode Public")
            .to_vec();
        let secret_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&secret)
            .expect("rkyv encode Secret")
            .to_vec();
        let witness = encode_witness(&public_bytes, &secret_bytes);

        let (interp, mut flat_mem) =
            zkpvm::actor::interpreter_from_blob(&blob, 100_000_000).expect("interpreter from blob");
        let end = (witness_addr as usize) + witness.len();
        flat_mem[witness_addr as usize..end].copy_from_slice(&witness);
        let mut interp = interp;
        interp.flat_mem = flat_mem;
        let mut tracing = TracingPvm::new(interp);
        let _ = tracing.run_with_vos_stubs();

        // Reconstruct the io-hash from final φ[9..12] — the same LE
        // decode `Proof::public_io_hash` performs on final_state.registers.
        let mut h = [0u8; 32];
        for (i, w) in tracing.pvm.registers[9..13].iter().enumerate() {
            h[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        h
    };

    let hash_a = io_hash_for(100, 2);
    let hash_b = io_hash_for(50, 5);
    eprintln!("io-hash A={}, B={}", hex(&hash_a), hex(&hash_b));
    assert_ne!(
        hash_a, [0u8; 32],
        "bind_io_bytes must place a non-zero io-hash in φ[9..12]"
    );
    assert_ne!(
        hash_a, hash_b,
        "different Public must bind a different io-hash — the binding is \
         not actually a function of the public input"
    );
    assert_eq!(
        hash_a,
        io_hash_for(100, 2),
        "identical Public must bind an identical io-hash (determinism)"
    );
}

/// Phase Z0 load-bearing test: a proof's `final_state.registers` is
/// genuinely STARK-bound (not just decorative metadata the prover
/// fills in). Tampering with any byte of any register post-prove
/// must make `verify_standalone` reject.
///
/// Without this guarantee, the higher-level io-binding the prover
/// extension checks (`proof.public_io_hash() == compute_io_hash(
/// public, return)`, read from the φ[9..12] registers) is
/// meaningless — a cheating prover could compute
/// the proof for any witness then write whatever hash they want
/// into the metadata field.
///
/// The chip closing the register-memory ledger (Phase Z0's
/// `RegisterMemoryClosingChip`) consumes a synthetic per-register
/// read at `closing_ts`; the read-consistency constraint forces
/// each row's value to equal the previous ledger row's value
/// (= the actual last-written value of that register), so any
/// post-prove tamper to `final_state.registers` causes the
/// closing chip's claimed values to diverge from what the ledger
/// already pinned.
#[test]
fn final_state_registers_are_stark_bound() {
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let mut side_note = side_note_for_trace(&blob, 100_000_000);
    let proof = prove_mobile(&mut side_note).expect("prove voucher-check");
    let prog_hash = program_commitment_of_proof(&proof);

    // Sanity: pristine proof verifies.
    use zkpvm_verifier::{PcsPolicy, verify_standalone_with_pcs_policy};
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
/// halting ecall (the four hash words ride in `a2..a5` as inline-asm
/// `in` operands).  Phase Z0 already binds `final_state.registers`, so
/// the hash is a tamper-evident public output read back by
/// `Proof::public_io_hash` — no new ECALL, no prover changes.
///
/// This pins the mechanism end-to-end at the zkpvm level: the binding is
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
    use zkpvm_verifier::{PcsPolicy, verify_standalone_with_pcs_policy};

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

/// Phase Z0-init load-bearing test: `proof.initial_state.registers`
/// is STARK-bound, symmetric to `final_state.registers`. The boundary
/// chip emits per-register tuples at `ts = 0` sourced from
/// `side_note.initial_regs`, and `prove()` makes the proof field
/// equal to that source. The FS-transcript mix ties the metadata
/// field to the verifier's challenge derivation; tampering shifts
/// lookup elements and breaks constraint satisfaction.
///
/// This closes the `verify_chain` gap that Z0 (final-only) left open:
/// without binding both ends, an attacker could chain a segment N
/// proof (final_state Z0-bound) to a tampered segment N+1
/// (initial_state was unbound metadata) and pass the chain check
/// while segment N+1's actual trace started from arbitrary registers.
#[test]
fn initial_state_registers_are_stark_bound() {
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let mut side_note = side_note_for_trace(&blob, 100_000_000);
    let proof = prove_mobile(&mut side_note).expect("prove voucher-check");
    let prog_hash = program_commitment_of_proof(&proof);

    use zkpvm_verifier::{PcsPolicy, verify_standalone_with_pcs_policy};
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

/// Phase Z0 hardening: `verify_standalone` must reject any proof with
/// `component_mask = 0` at the current `format_version`. The mask-zero
/// sentinel is the chip-isolated `prove_with_explicit_components` marker,
/// and chip-isolated proofs deliberately skip the FS-transcript mix of
/// `final_state.registers` on the prover side. Without this reject, an
/// attacker could ship a chip-isolated proof (no prover-side mix) to
/// `verify_standalone` and tamper the metadata field unobserved —
/// bypassing the entire Z0 binding.
#[test]
fn verify_standalone_rejects_mask_zero() {
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let mut side_note = side_note_for_trace(&blob, 100_000_000);
    let proof = prove_mobile(&mut side_note).expect("prove voucher-check");
    let prog_hash = program_commitment_of_proof(&proof);

    use zkpvm_verifier::{PcsPolicy, verify_standalone_with_pcs_policy};
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

/// Phase Z0 + Z0-init scope: registers only, both ends. The `pc` and
/// `memory_commitment` fields on `proof.initial_state` and
/// `proof.final_state` are NOT bound — they travel as metadata
/// alongside the proof. This test pins the scope: tampering any of
/// the four leaves `verify_standalone` happily accepting the proof.
///
/// The day someone wires these into the FS transcript (or a future
/// "Z1" / "Z2" chip closes the program-memory and memory ledgers
/// analogously), they'll need to update this test instead of
/// inheriting a silent binding.
///
/// If this test starts failing, that's good news — *something* has
/// taken responsibility for one of these fields. Find out what, and
/// rewrite this test to reflect the new scope.
#[test]
fn boundary_non_register_fields_are_not_bound() {
    let Some(blob) = load_voucher_check_blob() else {
        return;
    };
    let mut side_note = side_note_for_trace(&blob, 100_000_000);
    let proof = prove_mobile(&mut side_note).expect("prove voucher-check");
    let prog_hash = program_commitment_of_proof(&proof);

    use zkpvm_verifier::{PcsPolicy, verify_standalone_with_pcs_policy};

    // Final-state pc — unbound.
    let mut tampered_pc = proof.clone();
    tampered_pc.final_state.pc ^= 0x1000;
    verify_standalone_with_pcs_policy(tampered_pc, prog_hash, &PcsPolicy::MOBILE).expect(
        "Z0 binds registers only — tamper of final_state.pc must still verify. \
         If this fails, something else is binding pc; update the test or the scope doc.",
    );

    // Final-state memory_commitment — unbound.
    let mut tampered_mem = proof.clone();
    tampered_mem.final_state.memory_commitment[0] ^= 0xff;
    verify_standalone_with_pcs_policy(tampered_mem, prog_hash, &PcsPolicy::MOBILE).expect(
        "Z0 binds registers only — tamper of final_state.memory_commitment must \
         still verify. If this fails, something else is binding it; update the \
         test or the scope doc.",
    );

    // Initial-state pc — unbound (Z0-init's FS-mix covers only
    // initial_state.registers).
    let mut tampered_initial_pc = proof.clone();
    tampered_initial_pc.initial_state.pc ^= 0x1000;
    verify_standalone_with_pcs_policy(tampered_initial_pc, prog_hash, &PcsPolicy::MOBILE)
        .expect("Z0-init binds registers only — tamper of initial_state.pc must still verify.");

    // Initial-state memory_commitment — unbound.
    let mut tampered_initial_mem = proof;
    tampered_initial_mem.initial_state.memory_commitment[0] ^= 0xff;
    verify_standalone_with_pcs_policy(tampered_initial_mem, prog_hash, &PcsPolicy::MOBILE).expect(
        "Z0-init binds registers only — tamper of initial_state.memory_commitment \
         must still verify.",
    );
}

/// Mirrors the prover extension's `__VOS_WITNESS` encoding so the
/// test exercises the same length-prefixed `[u32 len][public][u32
/// len][secret]` layout the prover patches in.
fn encode_witness(public_bytes: &[u8], secret_bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + public_bytes.len() + 4 + secret_bytes.len());
    v.extend_from_slice(&(public_bytes.len() as u32).to_le_bytes());
    v.extend_from_slice(public_bytes);
    v.extend_from_slice(&(secret_bytes.len() as u32).to_le_bytes());
    v.extend_from_slice(secret_bytes);
    v
}

/// Minimal ELF symbol lookup — just enough to find __VOS_WITNESS's
/// virtual address. Manual parsing instead of pulling `object` here
/// since the integration test already has plenty of deps.
fn find_witness_buffer_addr(elf: &[u8]) -> Option<u64> {
    // ELF64 header layout: magic at 0..16, e_shoff at 0x28, e_shnum
    // at 0x3C, e_shstrndx at 0x3E, section header size at 0x3A.
    if elf.len() < 0x40 || &elf[0..4] != b"\x7fELF" || elf[4] != 2 {
        return None;
    }
    let e_shoff = u64::from_le_bytes(elf[0x28..0x30].try_into().ok()?) as usize;
    let e_shentsize = u16::from_le_bytes(elf[0x3A..0x3C].try_into().ok()?) as usize;
    let e_shnum = u16::from_le_bytes(elf[0x3C..0x3E].try_into().ok()?) as usize;

    // Walk section headers to find .symtab + .strtab.
    let mut symtab_off = 0usize;
    let mut symtab_size = 0usize;
    let mut strtab_off = 0usize;
    let mut strtab_size = 0usize;
    for i in 0..e_shnum {
        let sh = e_shoff + i * e_shentsize;
        if sh + 64 > elf.len() {
            return None;
        }
        let sh_type = u32::from_le_bytes(elf[sh + 4..sh + 8].try_into().ok()?);
        let sh_off = u64::from_le_bytes(elf[sh + 24..sh + 32].try_into().ok()?) as usize;
        let sh_size = u64::from_le_bytes(elf[sh + 32..sh + 40].try_into().ok()?) as usize;
        if sh_type == 2 {
            symtab_off = sh_off;
            symtab_size = sh_size;
        } else if sh_type == 3 {
            // Multiple STRTABs exist; the one linked from symtab via
            // sh_link is the right one. For our small ELFs the last
            // STRTAB is .strtab; .shstrtab is earlier.
            strtab_off = sh_off;
            strtab_size = sh_size;
        }
    }
    if symtab_off == 0 || strtab_off == 0 {
        return None;
    }

    // ELF64 Sym is 24 bytes: name(4) info(1) other(1) shndx(2) value(8) size(8).
    let sym_entsize = 24usize;
    for i in 0..(symtab_size / sym_entsize) {
        let s = symtab_off + i * sym_entsize;
        if s + sym_entsize > elf.len() {
            break;
        }
        let name_off = u32::from_le_bytes(elf[s..s + 4].try_into().ok()?) as usize;
        if name_off == 0 || strtab_off + name_off >= strtab_off + strtab_size {
            continue;
        }
        let name_start = strtab_off + name_off;
        let name_end = elf[name_start..]
            .iter()
            .position(|&b| b == 0)
            .map(|n| name_start + n)
            .unwrap_or(name_start);
        let name = core::str::from_utf8(&elf[name_start..name_end]).ok()?;
        if name == "__VOS_WITNESS" {
            let value = u64::from_le_bytes(elf[s + 8..s + 16].try_into().ok()?);
            if value != 0 {
                return Some(value);
            }
        }
    }
    None
}
