//! voucher-check — PVM guest binary whose execution IS the witness for a
//! `cipher_clerk::voucher::proof::check` proof.
//!
//! ## Two entry paths
//!
//! Both run `cipher_clerk::voucher::proof::check`; the difference is
//! how (Public, Secret) reach the function.
//!
//! 1. **`start` (lifecycle on_start hook)** — reads (Public, Secret)
//!    from the standard ZK witness buffer `__VOS_WITNESS` (declared via
//!    `vos::zk::witness_buffer!`). The host `prover` extension writes the
//!    rkyv-archived bytes into the flat-mem region backing that buffer
//!    before `TracingPvm::run` (locating it by ELF symbol name), and the
//!    trace ingests them via a normal `volatile_read`. Falls back to a
//!    hardcoded witness when the buffer is empty (e.g. a regular
//!    `vosx run` invocation, or a v0 smoke test).
//!
//! 2. **`verify_check(public_bytes, secret_bytes)` (mailbox message)**
//!    — production-shape path: take the witness as message args. Used
//!    when invoking the actor through the actor framework's normal
//!    INVOKE channel (cross-actor call from a host extension or
//!    another actor). The prove path doesn't currently use this —
//!    static BSS is deterministic per-ELF, mailbox payloads embed
//!    runtime-allocated pointers that drift between runs.
//!
//! Returns `1` on success, `0` if either argument fails to decode.
//! A check-rule violation panics inside `check` and surfaces as
//! `Trap` exit + non-zero panics counter.

use cipher_clerk::crypto::{Amount, AuthKey, Blinding};
use cipher_clerk::voucher::proof::{self, Public, Secret};
use vos::prelude::*;

// Standard ZK witness-injection buffer `__VOS_WITNESS` (1024 bytes: the
// current rkyv (Public ~128 B, Secret ~64 B) fits comfortably). The host
// `prover` extension patches opaque witness bytes here before tracing,
// located by the `__VOS_WITNESS` ELF symbol; `__vos_read_witness()` reads
// the conventional length-prefixed `(public, secret)` payload back. Bump
// the size if the witness grows.
vos::zk::witness_buffer!(1024);

#[actor]
struct VoucherCheck;

#[messages]
impl VoucherCheck {
    fn new() -> Self {
        VoucherCheck
    }

    /// Lifecycle `on_start` hook. Reads (Public, Secret) from
    /// `__VOS_WITNESS`; falls back to a hardcoded witness when the
    /// buffer's length prefix is zero. Calls
    /// `cipher_clerk::voucher::proof::check` — Trap on success,
    /// panic on rule violation.
    #[msg]
    async fn start(&self, _ctx: &mut Context<Self>) -> u8 {
        let (public, secret) = match read_witness() {
            Some((p, s)) => (p, s),
            None => hardcoded_witness(),
        };
        proof::check(&public, &secret);
        // ZK actor-IO ABI (tagless): bind this proof to the asserted
        // `Public` input and the `1` success return.  The hash lands in
        // the Phase-Z0-bound final-state registers φ[9..12] at halt; the
        // host verifier (the `prover` extension's `verify`) recomputes
        // `vos::zk::compute_io_hash(public_bytes, return_bytes)` and
        // checks equality, composed with the STARK-validity check against
        // voucher-check's program commitment.  No actor/message tag is
        // bound — the commitment is the program identity.
        vos::zk::bind_io(&public, &1u8);
        1
    }

    /// Mailbox message handler — production-shape (Public, Secret)
    /// passing via actor framework. See module docs for why the
    /// prove path uses `start` instead.
    #[msg]
    async fn verify_check(
        &self,
        _ctx: &mut Context<Self>,
        public_bytes: Vec<u8>,
        secret_bytes: Vec<u8>,
    ) -> u8 {
        let Ok(public) = vos::rkyv::from_bytes::<Public, vos::rkyv::rancor::Error>(&public_bytes)
        else {
            return 0;
        };
        let Ok(secret) = vos::rkyv::from_bytes::<Secret, vos::rkyv::rancor::Error>(&secret_bytes)
        else {
            return 0;
        };
        proof::check(&public, &secret);
        1
    }
}

/// Decode (Public, Secret) from the prover-patched `__VOS_WITNESS`
/// buffer (via the `witness_buffer!`-emitted `__vos_read_witness`).
/// Returns `None` if the buffer is unpatched or either rkyv archive
/// fails to decode — the caller falls back to the hardcoded witness.
/// The framework owns the volatile length-prefixed read; this actor
/// only owns the decode of its own `(Public, Secret)` layout.
fn read_witness() -> Option<(Public, Secret)> {
    let (public_bytes, secret_bytes) = __vos_read_witness()?;
    let public = vos::rkyv::from_bytes::<Public, vos::rkyv::rancor::Error>(&public_bytes).ok()?;
    let secret = vos::rkyv::from_bytes::<Secret, vos::rkyv::rancor::Error>(&secret_bytes).ok()?;
    Some((public, secret))
}

/// Fallback hardcoded (Public, Secret). Bytes are chosen so `check`
/// passes: `amount_commit == Pedersen(amount, blinding)` and
/// `sender_balance_before >= amount`. Used when the static buffer
/// hasn't been patched (regular invocation outside the prover).
fn hardcoded_witness() -> (Public, Secret) {
    let amount: u64 = 100;
    let amount_blinding =
        Blinding::from_bytes([2u8; 32]).expect("[2u8; 32] is a canonical Ristretto scalar");
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
        sender_balance_before: 1_000,
    };
    (public, secret)
}
