//! voucher-check — PVM guest whose traced execution IS the witness for a
//! **confidential state-transition** behind a `Mode::External` voucher.
//!
//! ## What it proves (conservation-of-value)
//!
//! The guest decodes a `(cipher_clerk::voucher::proof::Public,
//! cipher_clerk::snapshot::TransitionWitness)` pair from the standard ZK
//! witness buffer `__VOS_WITNESS` and PROVES, via
//! [`TransitionWitness::verify_transition`]:
//!
//! 1. the issuer's ledger snapshot has root == the voucher's bound
//!    `state_root_before` (balances are READ from that ledger, not
//!    asserted as a free input — the hole the old `voucher::proof::check`
//!    left open);
//! 2. applying the batch yields exactly `state_root_after`, with the
//!    kernel enforcing double-entry zero-sum, **no-overdraft**, idempotency
//!    and signatures; and
//! 3. every event applied cleanly.
//!
//! It then ties the voucher's `amount_commit` to a debit the batch
//! actually applied ([`TransitionWitness::has_debit_commit`]) and binds the
//! voucher's `public_bytes` into the proof's tagless io-hash. Any rule
//! violation panics → `Trap` → the proof won't verify.
//!
//! ## Witness injection
//!
//! The host `prover` extension patches the rkyv-archived `(Public,
//! TransitionWitness)` into `__VOS_WITNESS` (located by ELF symbol) before
//! `TracingPvm::run`. A bare `vosx run` (no injected witness) is not a
//! proving run; `start` returns early in that case — the prover always
//! injects a witness before tracing.

use cipher_clerk::snapshot::TransitionWitness;
use cipher_clerk::voucher::proof::{self, Public};
use vos::prelude::*;

// Standard ZK witness-injection buffer `__VOS_WITNESS`. A
// `TransitionWitness` carries the issuer's ledger snapshot (v0.1 full
// ledger) + the batch + commitment openings, so it is KB-scale, not the
// ~200 B of the old `(Public, Secret)`. 16 KiB fits a small / pilot
// ledger; the future succinct per-touched-leaf Merkle witness shrinks this
// back down. The buffer lives in `.bss` (static), distinct from the PVM
// heap the kernel re-execution allocates on.
vos::zk::witness_buffer!(16384);

#[actor]
struct VoucherCheck;

#[messages]
impl VoucherCheck {
    fn new() -> Self {
        VoucherCheck
    }

    /// Lifecycle `on_start` hook — the prove path. Reads `(Public,
    /// TransitionWitness)` from `__VOS_WITNESS`, proves the bound
    /// state-transition, ties the voucher to the proven debit, and binds
    /// the voucher `public_bytes` into the proof's io-hash.
    #[msg]
    async fn start(&self, _ctx: &mut Context<Self>) -> u8 {
        let Some((public, witness)) = read_witness() else {
            // No injected witness — not a proving run (e.g. a bare
            // `vosx run`). Nothing to prove; the prover always injects.
            return 1;
        };

        // 1. Conservation-of-value: the issuer's ledger at the bound
        //    `state_root_before` really transitions to `state_root_after`
        //    by applying this batch — balances read from the snapshot, no
        //    overdraft, double-entry, all kernel-enforced. Panics on any
        //    violation (≡ "the proof won't verify").
        witness.verify_transition(public.state_root_before, public.state_root_after);

        // 2. Tie THIS voucher to the proven debit: its `amount_commit` must
        //    be a debit the batch actually applied. Without this, a valid
        //    transition for an unrelated batch could be passed off as
        //    proving this voucher. (Always enforced when a witness is
        //    present — an empty batch has no debit and would be a
        //    root_before==root_after mint hole otherwise.)
        assert!(
            witness.has_debit_commit(&public.amount_commit),
            "voucher amount_commit is not a debit in the proven batch"
        );

        // 3. Bind the voucher's public inputs (tagless io-ABI). The host
        //    verifier (`prover` extension's `verify`) recomputes
        //    `compute_io_hash(public_bytes, [1])` and checks equality,
        //    composed with STARK validity against voucher-check's program
        //    commitment. The public encoding is unchanged from D1.
        let public_bytes = proof::public_bytes(&public);
        vos::zk::bind_io_bytes(&public_bytes, &[1u8]);
        1
    }
}

/// Decode `(voucher::Public, TransitionWitness)` from the prover-patched
/// `__VOS_WITNESS` buffer (via the `witness_buffer!`-emitted
/// `__vos_read_witness`). Returns `None` if the buffer is unpatched or
/// either rkyv archive fails to decode — `start` then treats it as a
/// non-proving run. The public half is the voucher `Public` (bound); the
/// secret half is the `TransitionWitness` (snapshot + openings + batch).
fn read_witness() -> Option<(Public, TransitionWitness)> {
    let (public_bytes, witness_bytes) = __vos_read_witness()?;
    let public = vos::rkyv::from_bytes::<Public, vos::rkyv::rancor::Error>(&public_bytes).ok()?;
    let witness =
        vos::rkyv::from_bytes::<TransitionWitness, vos::rkyv::rancor::Error>(&witness_bytes)
            .ok()?;
    Some((public, witness))
}
