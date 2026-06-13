#![cfg(all(feature = "prover", feature = "debug-internals"))]

//! task #7 repro: sweep `v·G` comb scalar-mult values and find which
//! ones break `RistrettoCombCompressChip` constraints. The passing
//! harness `harness_ristretto_fixed_base_e2e_with_memory` only ever
//! tests `Scalar::from(0x1234_5678_9abc_def0)`. cipher-clerk's
//! `Amount::commit(value, b)` drives the comb path with `value: u64`,
//! so we sweep small/edge u64 values (0 = identity is the prime
//! suspect) and report each one's row#/constraint# failure.
//!
//! Run:
//!   cargo test -p zkpvm --features debug-internals \
//!     --test comb_value_sweep sweep -- --nocapture

use zkpvm::SideNote;
use zkpvm::chips::{
    Blake2bBoundaryChip, ByteToBitsChip, MemoryChip, MemoryMerkleChip, MemoryPageChip,
    MemoryRootBoundaryChip, RistrettoCombAnchorChip, RistrettoCombCompressChip,
    RistrettoCombCompressOutputChip, RistrettoCombScalarBoundaryChip, RistrettoCombTableChip,
    RistrettoEcallChip, RistrettoFixedBaseConsumerChip,
};
use zkpvm::core::tracing::{RistrettoMemOp, ScalarMultKind};
use zkpvm::harness::MachineProverComponent;
use zkpvm::side_note::RistrettoCombCall;

/// Build a comb-call side_note for `value·G` and run the row-by-row
/// constraint asserter. Returns Ok(()) if all chips' constraints hold,
/// Err(panic-message) with the `row #X, constraint #N` on the first
/// violation.
fn check_value(value: u64) -> Result<(), String> {
    check_scalar(curve25519_dalek::scalar::Scalar::from(value))
}

fn check_scalar(scalar_value: curve25519_dalek::scalar::Scalar) -> Result<(), String> {
    let scalar = scalar_value.to_bytes();
    let basepoint = curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
    let out_bytes = (scalar_value * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT)
        .compress()
        .to_bytes();

    let scalar_ptr: u32 = 0;
    let point_ptr: u32 = 64;
    let output_ptr: u32 = 128;
    let ts: u64 = 1;

    let mut initial_memory = vec![0u8; 256];
    initial_memory[scalar_ptr as usize..scalar_ptr as usize + 32].copy_from_slice(&scalar);
    initial_memory[point_ptr as usize..point_ptr as usize + 32].copy_from_slice(&basepoint);

    let build = || {
        let mut side_note = SideNote::new(Vec::new(), Vec::new(), Vec::new());
        side_note.initial_memory = initial_memory.clone();
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
        side_note.ristretto_comb_calls.push(RistrettoCombCall {
            scalar,
            out_bytes,
            output_ptr,
            ts,
        });
        side_note.populate_ristretto_comb_counts();
        side_note.populate_ristretto_compress_counts();
        side_note
    };

    let components: &[&'static dyn MachineProverComponent] = &[
        &MemoryChip,
        &MemoryPageChip,
        &MemoryMerkleChip,
        &MemoryRootBoundaryChip,
        &Blake2bBoundaryChip,
        &RistrettoEcallChip,
        &RistrettoCombTableChip,
        &RistrettoCombAnchorChip,
        &RistrettoCombScalarBoundaryChip,
        &RistrettoFixedBaseConsumerChip,
        &RistrettoCombCompressChip,
        &RistrettoCombCompressOutputChip,
        &ByteToBitsChip,
    ];

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut side_note = build();
        zkpvm::debug_assert_constraints_explicit(&mut side_note, components);
    }));
    match result {
        Ok(()) => Ok(()),
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "<non-string panic>".to_string());
            Err(msg)
        }
    }
}

#[test]
fn sweep() {
    // Silence the per-row asserter chatter from non-failing chips by
    // routing the catch_unwind through a quiet hook only on failure.
    std::panic::set_hook(Box::new(|_| {}));

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
        0x1234_5678_9abc_def0, // known-good (the harness value)
        u64::MAX,
    ];

    let mut failures = Vec::new();
    for v in &values {
        match check_value(*v) {
            Ok(()) => eprintln!("value={v:#x} ({v}): OK"),
            Err(msg) => {
                // Keep only the first interesting line of the panic.
                let first = msg.lines().next().unwrap_or(&msg).to_string();
                eprintln!("value={v:#x} ({v}): FAIL — {first}");
                failures.push((*v, first));
            }
        }
    }

    // Full-width 256-bit scalars — the shape cipher-clerk's Schnorr
    // sig-verify (`s·G`) and key derivation (`sk·G`) drive onto the
    // comb path. These exercise high windows 16..64 with non-identity
    // table entries, which the u64 sweep above never touches.
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
    std::panic::set_hook(Box::new(|_| {}));
    for (name, s) in &wide_scalars {
        match check_scalar(*s) {
            Ok(()) => eprintln!("wide[{name}] hex={}: OK", hex32(&s.to_bytes())),
            Err(msg) => {
                let first = msg.lines().next().unwrap_or(&msg).to_string();
                eprintln!("wide[{name}] hex={}: FAIL — {first}", hex32(&s.to_bytes()));
                failures.push((0xffff_ffff_ffff_ffff, format!("wide[{name}]: {first}")));
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
        eprintln!("  value={v:#x} ({v}): {msg}");
    }
    assert!(
        failures.is_empty(),
        "comb-compress constraints must hold for every scalar (identity 0·G \
         included); {} case(s) regressed — see above",
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
