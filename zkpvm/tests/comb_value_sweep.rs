#![cfg(feature = "prover")]

//! Comb-path soundness sweep for the FIXED-BASE `v·G` scalar mult that
//! cipher-clerk drives: `Amount::commit(value, b)` = value·G + b·H
//! (Pedersen), Schnorr sig-verify (`s·G`), and key derivation (`sk·G`).
//! We sweep the scalar values cipher-clerk actually feeds the comb path
//! (small/edge u64s for `Amount::commit`, wide 256-bit scalars for
//! Schnorr/key-deriv) and assert each proves through the full
//! comb→compress→output chain — `0·G` (the Ristretto identity) is the
//! prime special case.
//!
//! Each value is checked in a **valid full-context trace**: a REAL PVM
//! trace with CPU steps + a `RistrettoEcall` + memory pages (built with
//! the same `fixed_base_real_side_note` shape that
//! `harness_ristretto_fixed_base_e2e_with_memory` /
//! `harness_ristretto_identity_compress_e2e` use), then PROVED AND
//! VERIFIED through the FULL active component set (`active_components` +
//! `prove_with_explicit_components` / `verify_with_explicit_components`,
//! i.e. the `prove_verify_active` path).  This makes the memory chips
//! satisfiable (real per-page ledger with a non-zero closing ts) AND
//! genuinely exercises the comb→compress→output chain end-to-end for
//! every scalar — a full STARK prove + verify, so both the per-row AIR
//! constraints (prove's OODS sanity check) and the cross-chip lookup
//! balance (verify's `claimed logup sum is not zero`) are checked.
//!
//! (The prior revision built a STEP-LESS `SideNote::new(empty, empty,
//! empty)`, so every value tripped the step-less MemoryChip group-end
//! constraint before the comb chips were ever reached — a false alarm,
//! not a comb-chip bug.)
//!
//! Run:
//!   cargo test -p zkpvm --features prover \
//!     --test comb_value_sweep sweep -- --nocapture --test-threads=1

use zkpvm::{
    FriConfig, PcsConfig, PcsPolicy, SideNote, prove_with_explicit_components,
    verify_with_explicit_components,
};

/// Build a full-system `SideNote` for one FIXED-BASE `scalar·G` ECALL by
/// running a REAL PVM trace (mirrors chip_isolated.rs's
/// `fixed_base_real_side_note`): a `LoadImm φ[7]=scalar_ptr` retargets the
/// scalar pointer, then `Ecalli 110` drives the fixed-base comb path, then
/// `Trap`.  CpuChip produces the RELATION-A tuple that anchors the
/// RistrettoEcallChip block ts, memory pages hold the real scalar/point/
/// output bytes, and the comb chips consume them — the same closed chain a
/// real cipher-clerk actor emits.
fn fixed_base_real_side_note(scalar: curve25519_dalek::scalar::Scalar) -> SideNote {
    use javm::PVM_REGISTER_COUNT;
    use javm::instruction::Opcode;
    use javm::interpreter::Interpreter;
    use zkpvm::core::tracing::{ECALL_RISTRETTO_SCALAR_MULT, ScalarMultKind, TracingPvm};

    let point_addr: u64 = 0x1000;
    let output_addr: u64 = 0x1020;
    let scalar_base: u64 = 0x1040;
    let mut flat_mem = vec![0u8; 0x4000];
    let basepoint = curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
    flat_mem[point_addr as usize..point_addr as usize + 32].copy_from_slice(&basepoint);
    flat_mem[scalar_base as usize..scalar_base as usize + 32].copy_from_slice(&scalar.to_bytes());
    let initial_memory = flat_mem.clone();

    // LoadImm φ[7] = scalar_base (1 opcode + 1 reg + 4 imm), Ecalli 110
    // (1 opcode + 4 imm), Trap.
    let imm = ECALL_RISTRETTO_SCALAR_MULT;
    let mut code: Vec<u8> = Vec::new();
    let mut bitmask: Vec<u8> = Vec::new();
    code.push(Opcode::LoadImm as u8);
    code.push(7u8);
    code.extend_from_slice(&(scalar_base as u32).to_le_bytes());
    bitmask.push(1);
    bitmask.extend_from_slice(&[0u8; 5]);
    code.push(Opcode::Ecalli as u8);
    code.push((imm & 0xff) as u8);
    code.push(((imm >> 8) & 0xff) as u8);
    code.push(((imm >> 16) & 0xff) as u8);
    code.push(((imm >> 24) & 0xff) as u8);
    bitmask.push(1);
    bitmask.extend_from_slice(&[0u8; 4]);
    code.push(Opcode::Trap as u8);
    bitmask.push(1);

    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[7] = scalar_base; // overwritten by the LoadImm
    regs[8] = point_addr;
    regs[9] = output_addr;

    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        flat_mem,
        1_000_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run_with_precompiles();
    assert_eq!(
        tracing.ristretto_records.len(),
        1,
        "expected exactly one ristretto record"
    );
    assert_eq!(
        tracing.ristretto_records[0].kind,
        ScalarMultKind::FixedBasepoint,
        "scalar·G with the basepoint must classify as FixedBasepoint (comb path)"
    );
    assert_eq!(
        tracing.ristretto_records[0].scalar,
        scalar.to_bytes(),
        "the trace read the wrong scalar — register/memory setup regressed"
    );

    let ristretto_records = std::mem::take(&mut tracing.ristretto_records);
    let ristretto_mem_ops = std::mem::take(&mut tracing.ristretto_mem_ops);
    let steps = tracing.into_trace();

    let mut side_note = SideNote::new(steps, code, bitmask).with_memory(initial_memory);
    side_note.ristretto_calls = ristretto_records;
    side_note.ristretto_mem_ops = ristretto_mem_ops;
    side_note.ingest_ristretto_boundary();
    side_note
}

/// PROVE + VERIFY `scalar·G` through the full active component set (the
/// `prove_verify_active` path the passing harnesses use).  Returns Ok(())
/// iff the STARK proves and verifies; Err(first failure line) otherwise —
/// captures both prove errors/panics (per-row AIR / OODS sanity check) and
/// verify errors (cross-chip lookup imbalance).
fn check_scalar(scalar_value: curve25519_dalek::scalar::Scalar) -> Result<(), String> {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut side_note = fixed_base_real_side_note(scalar_value);
        // The FULL active component set the real prover uses for this trace:
        // CpuChip + Memory{,Page,Merkle,RootBoundary} + Blake2bBoundary +
        // range/bitwise + RistrettoEcall + the comb chips (table/anchor/
        // scalar-boundary/fixed-base-consumer/compress/compress-output) +
        // ByteToBits.  Prove exercises every chip's AIR; verify closes the
        // comb→compress→output lookup chain.
        let components = zkpvm::active_components(&side_note);
        // Cheap PcsConfig — fast prove for a sweep (matches prove_verify_active).
        let config = PcsConfig {
            pow_bits: 5,
            fri_config: FriConfig::new(0, 1, 3, 1),
            lifting_log_size: None,
        };
        let proof = prove_with_explicit_components(&mut side_note, config, &components)
            .map_err(|e| format!("PROVE failed: {e:?}"))?;
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
            &components,
            &policy,
        )
        .map_err(|e| format!("VERIFY failed: {e:?}"))
    }));
    match outcome {
        Ok(inner) => inner,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "<non-string panic>".to_string());
            Err(format!("PANIC: {msg}"))
        }
    }
}

fn check_value(value: u64) -> Result<(), String> {
    check_scalar(curve25519_dalek::scalar::Scalar::from(value))
}

#[test]
fn sweep() {
    // Silence the per-row asserter chatter from non-failing chips.  The
    // catch_unwind still captures the panic payload (row #/constraint #).
    std::panic::set_hook(Box::new(|_| {}));

    // u64 scalars — the shape `Amount::commit(value, b)` drives onto the
    // comb path (`value: u64`).  0 = identity (0·G) is the prime suspect.
    let values: Vec<u64> = vec![
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        16,
        50,
        100,
        255,
        256,
        1000,
        0x1234_5678_9abc_def0, // the harness value
        u64::MAX,
    ];

    let mut failures = Vec::new();
    for v in &values {
        match check_value(*v) {
            Ok(()) => eprintln!("value={v:#x} ({v}): OK"),
            Err(msg) => {
                let first = msg.lines().next().unwrap_or(&msg).to_string();
                eprintln!("value={v:#x} ({v}): FAIL — {first}");
                failures.push((format!("{v:#x} ({v})"), first));
            }
        }
    }

    // Full-width 256-bit scalars — the shape cipher-clerk's Schnorr
    // sig-verify (`s·G`) and key derivation (`sk·G`) drive onto the comb
    // path.  These exercise high windows 16..64 with non-identity table
    // entries the u64 sweep never touches.
    let wide_scalars: Vec<(&str, curve25519_dalek::scalar::Scalar)> = vec![
        (
            "all-0xFF wide-reduced",
            curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&[0xFFu8; 64]),
        ),
        (
            "ascending wide-reduced",
            curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&{
                let mut b = [0u8; 64];
                for (i, x) in b.iter_mut().enumerate() {
                    *x = i as u8;
                }
                b
            }),
        ),
        (
            "0x55 wide-reduced",
            curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&[0x55u8; 64]),
        ),
        (
            "0xAA wide-reduced",
            curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&[0xAAu8; 64]),
        ),
        (
            "L-1 (group order minus one)",
            -curve25519_dalek::scalar::Scalar::from(1u64),
        ),
        (
            "top-byte-only canonical",
            curve25519_dalek::scalar::Scalar::from_bytes_mod_order({
                let mut b = [0u8; 32];
                b[31] = 0x0f; // stay below L
                b
            }),
        ),
    ];
    for (name, s) in &wide_scalars {
        match check_scalar(*s) {
            Ok(()) => eprintln!("wide[{name}] hex={}: OK", hex32(&s.to_bytes())),
            Err(msg) => {
                let first = msg.lines().next().unwrap_or(&msg).to_string();
                eprintln!("wide[{name}] hex={}: FAIL — {first}", hex32(&s.to_bytes()));
                failures.push((format!("wide[{name}]"), first));
            }
        }
    }

    // Restore default hook so the assertion below prints normally.
    let _ = std::panic::take_hook();

    eprintln!("\n=== SWEEP SUMMARY ===");
    eprintln!(
        "{} / {} cases failed",
        failures.len(),
        values.len() + wide_scalars.len()
    );
    for (v, msg) in &failures {
        eprintln!("  {v}: {msg}");
    }
    assert!(
        failures.is_empty(),
        "comb-compress constraints must hold for every cipher-clerk scalar \
         (identity 0·G included); {} case(s) failed — see above",
        failures.len()
    );
}

fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}
