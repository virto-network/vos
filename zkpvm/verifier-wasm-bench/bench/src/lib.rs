//! F2 spike measurement artifact: full-AIR `zkpvm-verifier` verification
//! compiled to wasm32-unknown-unknown, one export per embedded proof fixture.
//!
//! Return codes: 1 = proof verified, 0 = verification rejected, 2 = postcard
//! decode failed. The tamper fixture (one bit flipped deep in the proof body,
//! chosen at fixture-generation time so postcard still decodes) must return 0
//! — proving this build actually verifies rather than trivially succeeding.
//!
//! The crate itself is `#![no_std]` (alloc only). The linked graph still
//! carries wasm32 `std`, because the vos workspace pins serde with default
//! features (std) — the same graph shape an F3 runtime integration would
//! inherit today. std provides the global allocator and panic handler here.

#![no_std]

extern crate alloc;

use zkpvm_verifier::{verify_standalone_with_pcs_policy, CommitmentHash, PcsPolicy, Proof};

fn run(fixture: &[u8], policy: &PcsPolicy) -> u32 {
    let Ok((proof, commitment)) = postcard::from_bytes::<(Proof, CommitmentHash)>(fixture) else {
        return 2;
    };
    match verify_standalone_with_pcs_policy(proof, commitment, policy) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

/// Runtime-shaped entry point: verify a `(Proof, CommitmentHash)` postcard
/// fixture supplied in linear memory (policy: 0 = STANDARD, 1 = MOBILE).
/// This is how an F3 integration receives proofs (extrinsic bytes, not
/// baked-in data); in the fixtures-free size-measurement build it is what
/// keeps the whole verify path from being dead-code-eliminated.
///
/// # Safety
/// `ptr..ptr+len` must be a valid byte range in linear memory.
#[no_mangle]
pub unsafe extern "C" fn verify_supplied(ptr: *const u8, len: usize, policy: u32) -> u32 {
    let fixture = core::slice::from_raw_parts(ptr, len);
    let policy = if policy == 0 {
        PcsPolicy::STANDARD
    } else {
        PcsPolicy::MOBILE
    };
    run(fixture, &policy)
}

#[cfg(feature = "embed")]
macro_rules! fixture_export {
    ($fn_name:ident, $file:literal, $policy:ident) => {
        #[no_mangle]
        pub extern "C" fn $fn_name() -> u32 {
            static FIXTURE: &[u8] = include_bytes!(concat!("../../fixtures/", $file));
            run(FIXTURE, &PcsPolicy::$policy)
        }
    };
}

#[cfg(feature = "embed")]
mod embedded {
    use super::*;

    fixture_export!(verify_log12_standard, "log12_standard.bin", STANDARD);
    fixture_export!(verify_log12_mobile, "log12_mobile.bin", MOBILE);
    fixture_export!(verify_log14_standard, "log14_standard.bin", STANDARD);
    fixture_export!(verify_log14_mobile, "log14_mobile.bin", MOBILE);
    fixture_export!(verify_log16_standard, "log16_standard.bin", STANDARD);
    fixture_export!(verify_log16_mobile, "log16_mobile.bin", MOBILE);
    // Tampered copy of log12_standard — must return 0 (verification rejects).
    fixture_export!(verify_tamper, "tamper.bin", STANDARD);
}
