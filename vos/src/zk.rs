//! VOS ZK actor-IO ABI — TAGLESS binding.
//!
//! A framework-level convention for binding a zkpvm proof of an actor
//! handler to the specific `(public_inputs, return_value)` tuple a
//! caller asserts it ran on — placing that tuple's hash in
//! `final_state.registers` (φ[9..12]) so the caller can assert this
//! proof corresponds to this exact `(public, return)`. (SOUNDNESS
//! CAVEAT below: the register binding is currently complete only
//! against an honest prover — see step 2.)
//!
//! ## What the hash binds (and what it deliberately does NOT)
//!
//! The binding hash contains ONLY a domain/version separator and the
//! I/O bytes:
//!
//! ```text
//! H = blake2b_256( b"vos/zk/io/v1" || H_field(public) || H_field(return) )
//! ```
//!
//! It is **tagless**: no actor/message identity enters the hash.  That
//! is by design — identity lives where it can be *proven*, not merely
//! *claimed*:
//!
//! - **Which program** ran is established by the proof's *program
//!   commitment* (the preprocessed-trace Merkle root, see
//!   `zkpvm::program_commitment_of_proof`).  The verifier supplies a
//!   trusted commitment to `verify_standalone`, which rejects any proof
//!   of a different program.  A name-tag in the hash would be a third,
//!   redundant copy of identity — and a *claim* (a tag can be reused for
//!   different code) rather than a *proof* (a commitment cannot).
//! - **The human name** ("voucher-check") belongs in the provenance /
//!   catalog layer (program_id → trusted commitment), where naming,
//!   versioning, and governance actually live.
//! - **Which operation** within a multi-handler program, when a protocol
//!   needs to distinguish, is just another *public input* the actor
//!   folds into `public` — one concept (public inputs), not a separate
//!   "msg tag".
//!
//! So a complete identity check is `verify_standalone(proof, commitment)`
//! (which program — cryptographic) **AND** `proof.public_io_hash() ==
//! compute_io_hash(public, return)` (which I/O).  The two are composed in
//! the `prover` host extension's `verify`; there is intentionally no
//! standalone binding-only check here (using one without the other is
//! the footgun the composed form retires).
//!
//! ## How it fits together
//!
//! 1. The guest actor binds its `(public, return)` with [`bind_io`]
//!    (or computes the hash directly with [`compute_io_hash_typed`]).
//! 2. The actor's halt sequence places that hash into the final-state
//!    register window φ[9..12] (RISC-V `a2..a5`) via inline-asm `in`
//!    operands on the halting `ecall` (see `actors::run`'s
//!    `halt_with_output_bound`).  Phase Z0's closing chip pins the
//!    final-register columns and the verifier's boundary-binding check
//!    (`zkpvm::boundary_binding`, v5) equates `final_state.registers` to
//!    them — no new ECALL, no prover changes.  SOUNDNESS CAVEAT: that
//!    column is pinned to the trace's true final registers only by the
//!    register-ledger read-consistency, which is currently vacuous
//!    against a from-scratch prover (`prev_value` is a free witness), so
//!    a malicious prover can still forge this hash; closing that needs
//!    the register-ledger read-consistency fix (see
//!    `zkpvm::chips::register_memory_closing`). Sound against an honest
//!    prover today.
//! 3. The host verifier reconstructs the hash from the proof via
//!    [`zkpvm::Proof::public_io_hash`] and compares it against a locally
//!    recomputed [`compute_io_hash`] — alongside the STARK validity
//!    check against the trusted program commitment.
//!
//! The ABI version lives in the hash domain separator (`b"vos/zk/io/v1"`),
//! not in `PROOF_FORMAT_VERSION` (which is constraint-shape only): old
//! proofs leave φ[9..13] at their cold-start zero, so their
//! `public_io_hash` is `[0u8; 32]` and naturally fails the equality
//! check.

/// Domain separator + ABI version for the (outer) actor-IO hash.  Bumping
/// the trailing version rotates the binding so old proofs and old
/// verifiers cleanly fail the equality check rather than silently
/// cross-validating.
const IO_DOMAIN: &[u8] = b"vos/zk/io/v1";

/// Domain separator for the per-field inner hash.  Distinct from
/// [`IO_DOMAIN`] so a field digest can never be confused with a full
/// io-hash.
const IO_FIELD_DOMAIN: &[u8] = b"vos/zk/io-field/v1";

/// Inner reduction of one I/O field to a fixed-width 32-byte digest.
///
/// Hashing each field to a fixed width *before* combining is what makes
/// [`compute_io_hash`] injective at the public/return boundary: with raw
/// concatenation, `(public="AB", return="C")` and `(public="A",
/// return="BC")` would hash identically; with fixed-width inner digests
/// they cannot collide (short of a blake2b collision).
fn field_hash(bytes: &[u8]) -> [u8; 32] {
    crate::crypto::blake2b::blake2b_hash::<32>(IO_FIELD_DOMAIN, &[bytes])
}

/// Compute the 32-byte tagless actor-IO binding hash from the
/// already-encoded `public` and `return` bytes:
///
/// ```text
/// H = blake2b_256(
///       b"vos/zk/io/v1"            // domain + ABI version
///    || field_hash(public_bytes)   // 32 bytes, injective reduction
///    || field_hash(return_bytes)   // 32 bytes
/// )
/// ```
///
/// This is the canonical primitive: the guest binds with the same bytes
/// the host verifier recomputes from.  `public_bytes` / `return_bytes`
/// are whatever encoding the actor and caller agree on — in practice the
/// rkyv archive of the typed values (see [`compute_io_hash_typed`], which
/// is exactly `compute_io_hash(&public.encode(), &return_value.encode())`).
/// An empty slice is the well-defined "no asserted public / return"
/// value (the default a non-binding actor binds).
pub fn compute_io_hash(public_bytes: &[u8], return_bytes: &[u8]) -> [u8; 32] {
    let ph = field_hash(public_bytes);
    let rh = field_hash(return_bytes);
    crate::crypto::blake2b::blake2b_hash::<32>(IO_DOMAIN, &[ph.as_slice(), rh.as_slice()])
}

/// Typed convenience over [`compute_io_hash`]: rkyv-encode `public` and
/// `return_value`, then hash.  This is the encoding contract the guest
/// and host verifier share — a host that holds the typed values computes
/// the identical hash a guest that called [`bind_io`] bound, and a host
/// that holds only the wire bytes calls [`compute_io_hash`] directly with
/// those bytes.
///
/// e.g. `compute_io_hash_typed(&public, &1u8)`.
pub fn compute_io_hash_typed<P, R>(public: &P, return_value: &R) -> [u8; 32]
where
    P: crate::Encode,
    R: crate::Encode,
{
    compute_io_hash(&public.encode(), &return_value.encode())
}

// ── Witness-injection convention (`__VOS_WITNESS`) ───────────────────
//
// A provable actor takes its witness from a fixed, conventionally-named
// static buffer `__VOS_WITNESS` that the host `prover` extension patches
// with OPAQUE bytes (found by ELF symbol name) before tracing.  The
// prover never interprets the bytes — the actor owns its own layout — so
// the prover is program-agnostic.  The conventional payload layout (which
// [`read_witness_buffer`] and the prover's `encode_witness` agree on) is
// little-endian length-prefixed `(public, secret)`:
//
//   `[u32 public_len][public][u32 secret_len][secret]`
//
// Actors declare the buffer with the [`witness_buffer!`] macro instead of
// hand-rolling the `#[no_mangle] static mut`.

/// A `(public_bytes, secret_bytes)` witness read from a `__VOS_WITNESS`
/// buffer.  Both halves are opaque to the framework — the actor decodes
/// them with whatever scheme it bound (rkyv in practice).
pub type Witness = (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>);

/// Read a length-prefixed `(public, secret)` witness from a guest witness
/// buffer of capacity `cap` bytes starting at `ptr` (the
/// [`witness_buffer!`]-emitted `__VOS_WITNESS`).  Layout (little-endian):
/// `[u32 public_len][public][u32 secret_len][secret]`.
///
/// Returns `None` when the buffer is unpatched (leading length zero) or
/// malformed (a declared length runs past `cap`) — the actor then falls
/// back to whatever default it chooses.  Uses volatile reads so a
/// zero-initialised `.bss` buffer isn't optimised away on the guest.
///
/// # Safety
/// `ptr` must point to at least `cap` readable bytes for the duration of
/// the call (satisfied by the `witness_buffer!`-emitted static).
pub unsafe fn read_witness_buffer(ptr: *const u8, cap: usize) -> Option<Witness> {
    use alloc::vec::Vec;
    if cap < 8 {
        return None;
    }
    // SAFETY: caller guarantees `cap` readable bytes at `ptr`; every
    // offset below is bounds-checked against `cap` before the read.
    let public_len = unsafe { core::ptr::read_volatile(ptr as *const u32) } as usize;
    if public_len == 0 || 4usize.checked_add(public_len)?.checked_add(4)? > cap {
        return None;
    }
    let mut public = Vec::with_capacity(public_len);
    for i in 0..public_len {
        public.push(unsafe { core::ptr::read_volatile(ptr.add(4 + i)) });
    }
    let secret_off = 4 + public_len;
    let secret_len =
        unsafe { core::ptr::read_volatile(ptr.add(secret_off) as *const u32) } as usize;
    if secret_len == 0 || secret_off.checked_add(4)?.checked_add(secret_len)? > cap {
        return None;
    }
    let mut secret = Vec::with_capacity(secret_len);
    for i in 0..secret_len {
        secret.push(unsafe { core::ptr::read_volatile(ptr.add(secret_off + 4 + i)) });
    }
    Some((public, secret))
}

/// Declare the standard ZK witness-injection buffer `__VOS_WITNESS` of
/// `$n` bytes, plus a `__vos_read_witness()` helper that reads the
/// conventional length-prefixed `(public, secret)` payload back (see
/// [`read_witness_buffer`]).
///
/// Every provable actor exposes a `#[no_mangle] static mut __VOS_WITNESS`
/// so the host `prover` extension can patch opaque witness bytes into it
/// (located by ELF symbol name) before tracing.  Using this macro keeps
/// the symbol name and buffer shape consistent across actors so the
/// prover stays program-agnostic.
///
/// ```ignore
/// vos::zk::witness_buffer!(1024);
/// // ... later, in a handler:
/// let (public_bytes, secret_bytes) = __vos_read_witness().unwrap_or_else(default_witness);
/// ```
#[macro_export]
macro_rules! witness_buffer {
    ($n:expr) => {
        /// Witness buffer the host prover patches before tracing — see
        /// `vos::zk::witness_buffer!`.  Lives in `.bss` (all zeros until
        /// patched).
        #[unsafe(no_mangle)]
        static mut __VOS_WITNESS: [u8; $n] = [0u8; $n];

        /// Read the `(public, secret)` witness the prover patched into
        /// `__VOS_WITNESS`; `None` when unpatched or malformed.
        fn __vos_read_witness() -> ::core::option::Option<$crate::zk::Witness> {
            // SAFETY: `__VOS_WITNESS` is a `$n`-byte static; the reader
            // stays within `$n` bytes.
            unsafe {
                $crate::zk::read_witness_buffer(
                    ::core::ptr::addr_of!(__VOS_WITNESS) as *const u8,
                    $n,
                )
            }
        }
    };
}

#[doc(inline)]
pub use crate::witness_buffer;

// ── Guest-side binding (halt-asm path) ───────────────────────────────
//
// A service actor binds its `(public, return)` by computing the io-hash
// during execution and stashing it here; `actors::run::run_refine_service`
// reads the stash just before halt and places it in φ[9..12] via
// `halt_with_output_bound` (see this module's docs).  When no actor binds
// explicitly, `run_refine_service` falls back to the empty-public/
// empty-return default, so every proof carries a well-defined io-hash
// (never the cold-start zero sentinel).

/// Single-slot stash for the pending io-hash, set by [`bind_io`] during
/// handler execution and drained by `run_refine_service` at halt.
///
/// SAFETY: the PVM guest is strictly single-threaded, so the `static mut`
/// is never concurrently accessed — same invariant the runtime relies on
/// for `ACTOR_HOLDER` / `OUTPUT_BUF` in `actors::run`.
#[cfg(feature = "pvm")]
static mut PENDING_IO_HASH: Option<[u8; 32]> = None;

/// Stash a precomputed io-hash for the halt binding.  Internal — actors
/// call [`bind_io`].
#[cfg(feature = "pvm")]
#[doc(hidden)]
pub fn __set_pending_io_hash(hash: [u8; 32]) {
    let slot = core::ptr::addr_of_mut!(PENDING_IO_HASH);
    // SAFETY: single-threaded PVM; exclusive access via raw pointer.
    unsafe { *slot = Some(hash) };
}

/// Drain the pending io-hash.  Internal — `run_refine_service` calls this
/// once at halt.
#[cfg(feature = "pvm")]
#[doc(hidden)]
pub fn __take_pending_io_hash() -> Option<[u8; 32]> {
    let slot = core::ptr::addr_of_mut!(PENDING_IO_HASH);
    // SAFETY: single-threaded PVM; exclusive access via raw pointer.
    unsafe { (*slot).take() }
}

/// Guest-side: bind this execution to the asserted `(public, return)`
/// tuple (tagless — see the module docs on why no actor/message identity
/// enters the hash).
///
/// Computes [`compute_io_hash_typed`] and stashes it; `run_refine_service`
/// places it into the Phase-Z0-bound final-state register window φ[9..12]
/// at halt, making it the proof's [`zkpvm::Proof::public_io_hash`].  The
/// host verifier checks it against a recomputed `compute_io_hash` over the
/// same `(public, return)`.
///
/// Call this from a handler after the work it proves, e.g.
/// `vos::zk::bind_io(&public, &1u8)`.  The last binding in a refine wins
/// (one handler per proof is the model).  Actors that never call it bind
/// the empty-public/empty-return default.  If a program exposes multiple
/// provable operations, fold an operation discriminator into `public`.
#[cfg(feature = "pvm")]
pub fn bind_io<P, R>(public: &P, return_value: &R)
where
    P: crate::Encode,
    R: crate::Encode,
{
    __set_pending_io_hash(compute_io_hash_typed(public, return_value));
}

/// Guest-side: bind this execution to an asserted `(public, return)`
/// tuple supplied as **already-encoded bytes** — the raw-bytes
/// counterpart to [`bind_io`].
///
/// The tagless io-ABI is fundamentally "bytes" (see [`compute_io_hash`]),
/// so an actor that owns an explicit, canonical encoding of its public
/// inputs (rather than relying on the rkyv archive [`bind_io`] derives)
/// binds via this. The host verifier recomputes
/// `compute_io_hash(public_bytes, return_bytes)` over the same bytes — so
/// guest and verifier agree by construction, with no rkyv-layout /
/// cross-crate coupling.
///
/// e.g. `vos::zk::bind_io_bytes(&cipher_clerk::voucher::proof::public_bytes(&p), &[1u8])`.
/// Same halt/φ[9..12] placement and last-binding-wins semantics as
/// [`bind_io`].
#[cfg(feature = "pvm")]
pub fn bind_io_bytes(public_bytes: &[u8], return_bytes: &[u8]) {
    __set_pending_io_hash(compute_io_hash(public_bytes, return_bytes));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Encode;

    #[test]
    fn deterministic_and_nonzero() {
        let a = compute_io_hash_typed(&7u32, &1u8);
        let b = compute_io_hash_typed(&7u32, &1u8);
        assert_eq!(a, b, "same inputs must hash identically");
        assert_ne!(a, [0u8; 32], "a real binding is never the unbound sentinel");
    }

    #[test]
    fn public_value_changes_hash() {
        let a = compute_io_hash_typed(&7u32, &1u8);
        let b = compute_io_hash_typed(&8u32, &1u8);
        assert_ne!(a, b, "different public input must rebind");
    }

    #[test]
    fn return_value_changes_hash() {
        let a = compute_io_hash_typed(&7u32, &1u8);
        let b = compute_io_hash_typed(&7u32, &2u8);
        assert_ne!(a, b, "different return value must rebind");
    }

    #[test]
    fn empty_public_and_return_is_stable() {
        // The default a non-binding actor binds: empty public + empty
        // return still yields a stable, nonzero hash (it's the domain +
        // two field-hashes of empty, not the cold-start zero sentinel).
        let a = compute_io_hash(&[], &[]);
        assert_eq!(a, compute_io_hash(&[], &[]));
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn injective_across_field_boundary() {
        // Hash-then-combine must be injective at the public/return
        // boundary — the property raw concatenation lacked.
        let h1 = compute_io_hash(b"AB", b"C");
        let h2 = compute_io_hash(b"A", b"BC");
        assert_ne!(
            h1, h2,
            "(public=AB,return=C) must not collide with (public=A,return=BC)"
        );
    }

    #[test]
    fn typed_matches_byte_primitive() {
        // The exact contract the host verifier relies on: encoding the
        // typed values then hashing equals hashing the encoded bytes the
        // guest produced via `bind_io`.
        let public = 7u32;
        let ret = 1u8;
        assert_eq!(
            compute_io_hash_typed(&public, &ret),
            compute_io_hash(&public.encode(), &ret.encode()),
        );
    }

    /// `bind_io_bytes(a, b)` stashes exactly `compute_io_hash(a, b)` for
    /// the halt binding (and drains once). pvm-gated — the stash + drain
    /// helpers only exist on the guest tier. Run with `--features pvm`.
    #[cfg(feature = "pvm")]
    #[test]
    fn bind_io_bytes_stashes_compute_io_hash() {
        // No other test touches PENDING_IO_HASH, so the single-slot stash
        // is uncontended; clear any leftover defensively.
        let _ = __take_pending_io_hash();
        bind_io_bytes(b"explicit-public", b"\x01");
        assert_eq!(
            __take_pending_io_hash(),
            Some(compute_io_hash(b"explicit-public", b"\x01")),
            "bind_io_bytes must stash compute_io_hash of the same bytes"
        );
        assert_eq!(
            __take_pending_io_hash(),
            None,
            "the slot must drain after one take"
        );
    }
}
