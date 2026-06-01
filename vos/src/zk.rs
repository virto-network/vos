//! VOS ZK actor-IO ABI.
//!
//! A framework-level convention for binding a zkpvm proof of an actor
//! handler to the specific `(public_inputs, return_value)` tuple a
//! caller asserts it ran on — turning Phase Z0's STARK-bound
//! `final_state.registers` from "the registers are bound" into "the
//! caller can assert this proof corresponds to this exact `(public,
//! return)`".
//!
//! ## How it fits together
//!
//! 1. The guest actor computes the 32-byte binding hash with
//!    [`compute_io_hash`] and emits [`ecall_zk_bind`].
//! 2. Under the zkpvm tracer, `handle_zk_bind_ecall` reads those 32
//!    bytes and writes them into the final-state register window
//!    φ[9..13]; Phase Z0's closing chip STARK-binds those registers.
//! 3. The verifier reconstructs the hash from the proof via
//!    [`zkpvm::Proof::public_io_hash`] and compares it against a
//!    locally recomputed [`compute_io_hash`] — see [`verify_actor_io`].
//!
//! The ABI version lives in the hash domain separator (`b"vos/zk/io/v1"`),
//! not in `PROOF_FORMAT_VERSION` (which is constraint-shape only): old
//! proofs leave φ[9..13] at their cold-start zero, so their
//! `public_io_hash` is `[0u8; 32]` and naturally fails the equality
//! check.

/// ECALL id for the ZK actor-IO binding hostcall.
///
/// MUST equal `zkpvm::core::ecall::ECALL_ZK_BIND` (and its mirror in
/// `zkpvm/precompiles/src/ecalls.rs`): the guest emits `ecalli` with
/// this immediate and the prover's tracer matches on it.  Defined here
/// independently because the guest (riscv64, no_std) cannot depend on
/// the host-only `zkpvm` crate — the same mirroring pattern as
/// [`crate::crypto::blake2b`]'s local `ECALL_BLAKE2B_COMPRESS`.
pub const ECALL_ZK_BIND: u32 = 115;

/// Domain separator + ABI version for the actor-IO hash.  Bumping the
/// trailing version rotates the binding so old proofs and old verifiers
/// cleanly fail the equality check rather than silently cross-validating.
const IO_DOMAIN: &[u8] = b"vos/zk/io/v1";

/// Domain separator for the per-type 8-byte identity reduction.
const TYPEID_DOMAIN: &[u8] = b"vos/zk/typeid/v1";

/// Stable 8-byte identity of a type, derived from its canonical name.
///
/// Uses [`core::any::type_name`] (NOT [`core::any::TypeId`], whose
/// 128-bit value is not stable across rustc versions) reduced through
/// blake2b to 8 bytes.  Deterministic for a given (type, toolchain), so
/// a prover and verifier built from the same toolchain agree.  Computed
/// at runtime — `type_name` is not `const` on the pinned toolchain.
fn type_id<T: ?Sized>() -> [u8; 8] {
    crate::crypto::blake2b::blake2b_hash::<8>(TYPEID_DOMAIN, &[core::any::type_name::<T>().as_bytes()])
}

/// Compute the 32-byte actor-IO binding hash for a `(public, return)`
/// pair under actor type `A` and message type `M`:
///
/// ```text
/// H = blake2b_256(
///       b"vos/zk/io/v1"             // domain + ABI version
///    || type_id::<A>()  (8 bytes)   // actor identity
///    || type_id::<M>()  (8 bytes)   // message identity
///    || rkyv(public)                // empty if no #[zk_public] args
///    || rkyv(return)                // () encodes empty
/// )
/// ```
///
/// `A` and `M` are phantom type parameters used only for identity;
/// `public: &P` and `return_value: &R` are the actual values, with
/// `P`/`R` inferred — e.g.
/// `compute_io_hash::<VoucherCheck, VerifyCheck>(&public, &1u8)`.
///
/// Encoding note: the rkyv archives of `public` and `return_value` are
/// concatenated without a length delimiter.  For a fixed `(A, M)` the
/// types `P` and `R` are fixed and the verifier recomputes with the
/// SAME types, so this is unambiguous for fixed-layout types (every
/// real handler today).  A handler whose `#[zk_public]` argument or
/// return type is variable-length (e.g. `Vec`) should length-prefix at
/// the type level if it needs injectivity at the public/return boundary.
pub fn compute_io_hash<A, M, P, R>(public: &P, return_value: &R) -> [u8; 32]
where
    P: crate::Encode,
    R: crate::Encode,
{
    let actor_id = type_id::<A>();
    let message_id = type_id::<M>();
    let public_bytes = public.encode();
    let return_bytes = return_value.encode();
    crate::crypto::blake2b::blake2b_hash::<32>(
        IO_DOMAIN,
        &[
            actor_id.as_slice(),
            message_id.as_slice(),
            public_bytes.as_slice(),
            return_bytes.as_slice(),
        ],
    )
}

/// Guest-side: emit the ZK actor-IO binding hostcall.
///
/// `ptr`/`len` address a 32-byte hash (the output of [`compute_io_hash`])
/// in guest memory; `len` must be ≥ 32.  Under the zkpvm tracer the host
/// reads those 32 bytes and writes them into the final-state register
/// window φ[9..13]; under the normal vos runtime the call is an inert
/// binding marker (the runtime does not interpret ECALL 115).
///
/// Per the [`crate::abi::pvm::ecall`] shim → grey-transpiler mapping,
/// `ecall2(id, ptr, len)` lands `ptr` in φ[7] and `len` in φ[8] — the
/// registers the tracer's `handle_zk_bind_ecall` reads.  This call does
/// not dereference `ptr` itself; the host reads the bytes out of
/// `flat_mem`.
#[cfg(feature = "pvm")]
pub fn ecall_zk_bind(ptr: *const u8, len: usize) -> u64 {
    crate::abi::pvm::ecall::ecall2(ECALL_ZK_BIND, ptr as u64, len as u64)
}

/// Verifier-side: check that `proof` is bound to the asserted
/// `(public, expected_return)` tuple for actor `A` / message `M`.
///
/// Returns `true` iff the proof's STARK-committed io-hash
/// ([`zkpvm::Proof::public_io_hash`], read from the Z0-bound final-state
/// registers) equals a locally recomputed [`compute_io_hash`].
///
/// # SECURITY — binding check, NOT proof verification
///
/// This establishes *which* `(public, return)` a **valid** proof
/// corresponds to; it does NOT establish that the proof is
/// cryptographically valid.  Callers MUST independently verify the
/// STARK proof itself against the trusted program commitment (e.g.
/// `zkpvm_verifier::verify_standalone_with_pcs_policy`).  Using
/// `verify_actor_io` alone would accept a forged proof carrying any
/// chosen register window.  The intended pattern is:
///
/// ```ignore
/// // 1. STARK validity against the program the verifier trusts:
/// verify_standalone_with_pcs_policy(proof.clone(), trusted_prog_commitment, &policy)?;
/// // 2. binding to the asserted (public, return):
/// if !vos::zk::verify_actor_io::<A, M>(&proof, &public, &expected_return) {
///     return reject;
/// }
/// ```
#[cfg(feature = "zk-verify")]
pub fn verify_actor_io<A, M, P, R>(
    proof: &zkpvm_verifier::Proof,
    public: &P,
    expected_return: &R,
) -> bool
where
    P: crate::Encode,
    R: crate::Encode,
{
    proof.public_io_hash() == compute_io_hash::<A, M, P, R>(public, expected_return)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Distinct marker types so `type_id` (via `type_name`) differs.
    struct ActorA;
    struct ActorB;
    struct MsgX;
    struct MsgY;

    #[test]
    fn deterministic_and_nonzero() {
        let a = compute_io_hash::<ActorA, MsgX, u32, u8>(&7u32, &1u8);
        let b = compute_io_hash::<ActorA, MsgX, u32, u8>(&7u32, &1u8);
        assert_eq!(a, b, "same inputs must hash identically");
        assert_ne!(a, [0u8; 32], "a real binding is never the unbound sentinel");
    }

    #[test]
    fn public_value_changes_hash() {
        let a = compute_io_hash::<ActorA, MsgX, u32, u8>(&7u32, &1u8);
        let b = compute_io_hash::<ActorA, MsgX, u32, u8>(&8u32, &1u8);
        assert_ne!(a, b, "different public input must rebind");
    }

    #[test]
    fn return_value_changes_hash() {
        let a = compute_io_hash::<ActorA, MsgX, u32, u8>(&7u32, &1u8);
        let b = compute_io_hash::<ActorA, MsgX, u32, u8>(&7u32, &2u8);
        assert_ne!(a, b, "different return value must rebind");
    }

    #[test]
    fn actor_identity_changes_hash() {
        // Cross-actor confusion guard: same (public, return, message)
        // under a different actor type must produce a different binding.
        let a = compute_io_hash::<ActorA, MsgX, u32, u8>(&7u32, &1u8);
        let b = compute_io_hash::<ActorB, MsgX, u32, u8>(&7u32, &1u8);
        assert_ne!(a, b, "actor_type_id must enter the hash");
    }

    #[test]
    fn message_identity_changes_hash() {
        let a = compute_io_hash::<ActorA, MsgX, u32, u8>(&7u32, &1u8);
        let b = compute_io_hash::<ActorA, MsgY, u32, u8>(&7u32, &1u8);
        assert_ne!(a, b, "message_type_id must enter the hash");
    }

    #[test]
    fn empty_public_and_return_is_stable() {
        // The "no #[zk_public] args, no return" case: `()` rkyv-encodes
        // to empty bytes but the domain + type-ids still yield a stable,
        // nonzero binding.
        let a = compute_io_hash::<ActorA, MsgX, (), ()>(&(), &());
        assert_eq!(a, compute_io_hash::<ActorA, MsgX, (), ()>(&(), &()));
        assert_ne!(a, [0u8; 32]);
    }
}
