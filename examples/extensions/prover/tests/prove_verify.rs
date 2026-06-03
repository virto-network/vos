//! General prove/verify e2e for the program-agnostic `prover` extension.
//!
//! Proves the voucher-check guest through the GENERAL path
//! (`prove_program(b"voucher-check", witness)` — no voucher knowledge in
//! the prover) and exercises the composed, tagless `verify_proof_bytes`:
//!
//!   1. happy path  — a proof of witness P verifies against the canonical
//!      program commitment AND the asserted I/O `(P, 1)`;
//!   2. mismatch    — the same proof rejects when verified against a
//!      DIFFERENT public P′ (caught by the tagless io-binding, which only
//!      works because G5's witness injection bound the *caller's* public);
//!   3. cross-program — the same proof rejects against a DIFFERENT program
//!      commitment (caught by `verify_standalone`, the program-identity
//!      anchor — NOT the io-hash).
//!
//! These are the first tests to assert a host-recomputed
//! `vos::zk::compute_io_hash` equals a real proof's `public_io_hash`, so
//! they also pin the guest/host encoding agreement. The witness is encoded
//! with `vos::rkyv` so it matches byte-for-byte what the guest decodes and
//! rebinds.
//!
//! Skips (does not fail) when the voucher-check ELF isn't built — mirror
//! the zkpvm smoke-test convention. Build it with `just build-voucher-check`.

use std::path::PathBuf;

use cipher_clerk::crypto::{Amount, AuthKey, Blinding};
use cipher_clerk::voucher::proof::{Public, Secret};
use prover_extension::{
    program_commitment_bytes, prove_program, prove_with_details, verify_proof_bytes,
};
use vos::Encode;

const PROGRAM: &[u8] = b"voucher-check";

/// Build a `(Public, Secret)` that passes `cipher_clerk::voucher::proof::
/// check` (commitment matches, balance ≥ amount). Distinct `amount` /
/// `blinding_byte` yield a distinct `Public` → distinct io-binding.
fn witness(amount: u64, blinding_byte: u8) -> (Public, Secret) {
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
    (public, secret)
}

/// Encode the `__VOS_WITNESS` payload: `[u32 public_len][public][u32
/// secret_len][secret]` (little-endian) — the convention the actor reads.
fn encode_witness(public_bytes: &[u8], secret_bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + public_bytes.len() + secret_bytes.len());
    v.extend_from_slice(&(public_bytes.len() as u32).to_le_bytes());
    v.extend_from_slice(public_bytes);
    v.extend_from_slice(&(secret_bytes.len() as u32).to_le_bytes());
    v.extend_from_slice(secret_bytes);
    v
}

fn voucher_check_elf_path() -> PathBuf {
    if let Ok(p) = std::env::var("VOUCHER_CHECK_ELF") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("actors")
        .join("voucher-check")
        .join("target")
        .join("riscv64em-javm")
        .join("release")
        .join("voucher-check.elf")
}

/// Full prove → verify round-trip plus the two adversarial rejections.
/// One witness-bearing prove (the proof under test) + one witness-free
/// prove (the canonical commitment) — proving the two agree is itself the
/// check that witness injection didn't shift the program's `log_sizes`.
#[test]
fn prove_verify_roundtrip_mismatch_and_cross_program() {
    if !voucher_check_elf_path().exists() {
        eprintln!("SKIP: voucher-check ELF not built — run `just build-voucher-check`");
        return;
    }

    // Prove over the caller's witness P (amount 100, blinding 2).
    let (public, secret) = witness(100, 2);
    // `.encode()` is `vos::Encode` (rkyv) — byte-identical to what the
    // guest's `bind_io(&public, &1u8)` and `read_witness` produce.
    let public_bytes = public.encode();
    let secret_bytes = secret.encode();
    let return_bytes = 1u8.encode(); // voucher-check binds the `1u8` success return.
    let witness_buf = encode_witness(&public_bytes, &secret_bytes);

    let (proof_bytes, proof_commitment, _io) =
        prove_with_details(PROGRAM, &witness_buf).expect("prove voucher-check over caller witness");
    let commitment = program_commitment_bytes(PROGRAM).expect("pinned program commitment");

    // Drift guard: the pinned commitment must equal a freshly-proven real
    // proof's commitment. If this fails, voucher-check.elf was rebuilt with
    // a shape-changing change — re-pin `VOUCHER_CHECK_COMMITMENT`.
    assert_eq!(
        commitment, proof_commitment,
        "pinned VOUCHER_CHECK_COMMITMENT drifted from the current ELF — re-pin it"
    );

    // 1. Happy path: valid STARK against the pinned commitment AND the
    //    io-binding to the asserted (P, 1).
    assert!(
        verify_proof_bytes(&commitment, &proof_bytes, &public_bytes, &return_bytes),
        "a proof of witness P must verify against the pinned commitment and \
         the asserted (public, return)"
    );

    // 2. Mismatch: a DIFFERENT public P′ must reject via the tagless
    //    io-binding (proof.public_io_hash != compute_io_hash(P′, 1)). This
    //    only bites because G5 bound the *caller's* P into the proof.
    let other_public_bytes = witness(50, 5).0.encode();
    assert!(
        !verify_proof_bytes(
            &commitment,
            &proof_bytes,
            &other_public_bytes,
            &return_bytes
        ),
        "verifying against a different public must reject — the io-binding \
         is not actually a function of the proven public input"
    );

    // 2b. A different asserted return must also reject.
    let other_return_bytes = 0u8.encode();
    assert!(
        !verify_proof_bytes(
            &commitment,
            &proof_bytes,
            &public_bytes,
            &other_return_bytes
        ),
        "verifying against a different return value must reject"
    );

    // 3. Cross-program: a DIFFERENT program commitment must reject via
    //    verify_standalone (program identity), NOT the io-hash. Tamper one
    //    byte of the real commitment to stand in for another program's.
    let mut wrong_commitment = commitment;
    wrong_commitment[0] ^= 1;
    assert!(
        !verify_proof_bytes(
            &wrong_commitment,
            &proof_bytes,
            &public_bytes,
            &return_bytes
        ),
        "verifying against the wrong program commitment must reject via \
         verify_standalone — program identity rests on the commitment, not \
         the (tagless) io-hash"
    );
}

/// Fast logic checks (no proving): program-id resolution + verify guards.
#[test]
fn unknown_program_and_malformed_inputs_reject() {
    // Unknown program_id resolves to no ELF → prove yields nothing.
    assert!(
        prove_program(b"no-such-program", &[]).is_none(),
        "an unknown program_id must not resolve to an ELF"
    );
    assert!(
        program_commitment_bytes(b"no-such-program").is_none(),
        "an unknown program_id has no commitment"
    );

    // Malformed verify inputs reject without panicking — in particular a
    // non-32-byte commitment must NOT reach the panicking `CommitmentHash`
    // ctor, and undecodable proof bytes are rejected.
    assert!(
        !verify_proof_bytes(&[0u8; 31], b"x", b"p", b"r"),
        "short commitment must reject"
    );
    assert!(
        !verify_proof_bytes(&[0u8; 32], b"not-a-proof", b"p", b"r"),
        "garbage proof must reject"
    );
}
