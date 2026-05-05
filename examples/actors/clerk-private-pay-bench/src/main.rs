//! cipher-clerk private-payment bench — what a user actually proves
//! on-device for one tap-and-pay (L2 graph privacy: sender↔recipient
//! link is hidden from the bank ledger).
//!
//! Mirrors the on-device half of `cipher_clerk::notes::seal` (see
//! `cipher-clerk/examples/shielded_send.rs`):
//!   - one Pedersen amount commit on the kernel transfer (hides value),
//!   - one Schnorr-on-Ristretto sign of the transfer's signing payload,
//!   - one note commitment (Pedersen with blake2b_512-derived value
//!     scalar over `asset_tag || value || owner || rho`),
//!   - rkyv archive of the signing payload (the on-wire bytes).
//!
//! The chain-side work — Schnorr verify, Pedersen reveal, Merkle pool
//! insertion, nullifier check — happens server-side and is NOT what a
//! user proves on their phone. Nullifier derivation also doesn't
//! happen on the payer's device (only the receiver knows the spend
//! key); that workload belongs in a future `prove_open_payment` bench.
//!
//! Randomness is seeded deterministically via blake2b_256 so the
//! prove path is reproducible. CryptoRng is a marker trait — for a
//! benchmark this is a fine stand-in for OsRng (which isn't available
//! under no_std/PVM anyway).

use vos::{actor, messages};
vos::pvm_main!(crate::ClerkPrivatePayBench);

use cipher_clerk::prelude::*;
use cipher_clerk::ids::{AccountId, EntryId, TransferId, TxTemplateId};
use cipher_clerk::types::Entry;
use cipher_clerk::notes::Note;
// `#[messages]` aliases `Result<T>` to the actor's fallible result, so
// reach for the std/core variant explicitly when we need the 2-arg form.
use core::result::Result as StdResult;
use rand_core::RngCore as _;

// cipher-clerk's `signing` feature transitively enables
// `rand_core/getrandom`, which won't link on the riscv64em-javm target
// without a custom backend.  We never actually call OsRng (DetRng
// supplies all randomness) so the stub returns UNSUPPORTED — if
// anything ever invokes it, the call site will surface a clear error
// instead of silently using zeros.
getrandom::register_custom_getrandom!(__pvm_stub_getrandom);
fn __pvm_stub_getrandom(_dest: &mut [u8]) -> StdResult<(), getrandom::Error> {
    Err(getrandom::Error::from(core::num::NonZeroU32::new(1).unwrap()))
}

#[actor]
struct ClerkPrivatePayBench;

#[messages]
impl ClerkPrivatePayBench {
    fn new() -> Self { ClerkPrivatePayBench }

    /// Run one tap-and-pay locally: build + sign + commit a single
    /// shielded send.  Returns a digest over the on-wire payload so
    /// the compiler can't dead-code-eliminate the work.
    ///
    /// **Phase 1 (current)**: skips the Ristretto scalar mults
    /// (`Amount::commit`, `Note::commitment`, Schnorr sign) — without
    /// a Ristretto precompile chip, ~14M PVM steps per scalar mul
    /// blows the ~50M-step proving budget for a 1-second prove.  Uses
    /// pre-baked commitment bytes + a placeholder signature instead.
    /// What's left exercises the bulk of the data-shape work the user's
    /// device actually does: blake2b for the note value scalar, rkyv
    /// archive of the signing payload, and the per-byte folds the
    /// MemoryChip has to ledger.
    ///
    /// **Phase 2 (planned)**: re-enable the scalar mults once we land
    /// a `RistrettoChip` precompile (analogue of `Blake2bChip`).  Until
    /// then this bench measures *everything except* the curve work, so
    /// we know the ceiling we have to fit under.
    #[msg]
    async fn start(&self, _ctx: &mut Context<Self>) -> u64 {
        let mut rng = DetRng::seed(*b"clerk-private-pay-bench-seed-v01");

        let alice_pk = AuthKey([0x11u8; 32]);
        let recipient_pk = AuthKey([0x42u8; 32]);
        let pool_pk = AuthKey([0x55u8; 32]);

        let journal = JournalId([7u8; 16]);
        let alice = Account::new(
            AccountId([1u8; 16]), journal, alice_pk,
            Iso4217::USD, BankCode::Checking, Direction::Credit,
        );
        let pool = Account::new(
            AccountId([2u8; 16]), journal, pool_pk,
            Iso4217::USD, BankCode::Checking, Direction::Debit,
        );

        let value: u64 = 50;

        // Step 1 (zkpvm-precompiles shim) — issue the Ristretto
        // scalar-mult ECALL so the on-target asm path is exercised
        // by the binary.  In the gated-off chip prover this returns
        // [0u8; 32] (the shim host-fallback would return real bytes,
        // but the actor runs on PVM where the chip handler captures
        // the call).  Used here purely to pin the asm instantiation;
        // when R1f's full integration lands, this becomes the real
        // call site for `Amount::commit`.
        let mut probe_scalar = [0u8; 32]; probe_scalar[0] = (value as u8) ^ 0x5a;
        let mut probe_point = [0u8; 32]; probe_point[0] = 0xed;
        let _probe_out = zkpvm_precompiles::ristretto_scalar_mult(&probe_scalar, &probe_point);

        // Pre-baked Pedersen-commit bytes (would be `Amount::commit(value,
        // &blinding)` once we have a Ristretto precompile).  Random-looking
        // 32 bytes from the RNG so they don't compress to identity.
        let mut amt_bytes = [0u8; 32];
        rng.fill_bytes(&mut amt_bytes);
        let amt = Amount(amt_bytes);

        // Note commitment also pre-baked.  The blake2b half (value scalar)
        // is what we DO want to measure — fold it manually so the trace
        // shows the same hash work without the scalar mul.
        let mut rho = [0u8; 32];
        rng.fill_bytes(&mut rho);
        {
            use blake2::digest::{Update, VariableOutput};
            let mut h = blake2::Blake2bVar::new(64).unwrap();
            h.update(b"cipher-clerk/notes/commitment");
            h.update(&Iso4217::USD.as_ledger_id().to_le_bytes());
            h.update(&value.to_le_bytes());
            h.update(&recipient_pk.0);
            h.update(&rho);
            let mut wide = [0u8; 64];
            h.finalize_variable(&mut wide).unwrap();
            // Drop wide — we just wanted the blake2b work in-trace.
            for b in wide.iter() {
                core::hint::black_box(*b);
            }
        }

        // Construct Transfer + entries manually with deterministic IDs.
        // `Transfer::builder` calls `TransferId::random()` /
        // `EntryId::random()` which route through `OsRng` — fine off-VM,
        // but on PVM there is no entropy source so OsRng panics.
        let transfer_id = TransferId([0xA0u8; 16]);
        let entry_debit = Entry::debit(
            EntryId([0xE1u8; 16]), transfer_id, journal,
            alice.id, Layer::Settled, amt, alice.ledger, alice.code,
        );
        let entry_credit = Entry::credit(
            EntryId([0xE2u8; 16]), transfer_id, journal,
            pool.id, Layer::Settled, amt, pool.ledger, pool.code,
        );
        let unsigned = Transfer::new(
            transfer_id, journal, TxTemplateId::ZERO,
            alloc::vec![entry_debit, entry_credit],
            alloc::vec::Vec::new(),
        );

        // Placeholder signature: 64 random bytes split r||s.  The real
        // path runs SecretKey::sign, which is two Ristretto scalar mults
        // + one blake2b_512 — gated on the Ristretto precompile.
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        rng.fill_bytes(&mut r);
        rng.fill_bytes(&mut s);
        let mut signed = unsigned;
        signed.signatures = alloc::vec![Signature { r, s }];

        let payload = signed.signing_payload();

        let mut digest: u64 = 0;
        for &b in payload.iter() {
            digest = digest.wrapping_add(b as u64).rotate_left(7);
        }
        for &b in &amt.0 {
            digest = digest.wrapping_add(b as u64).rotate_left(13);
        }
        digest
    }
}

/// Deterministic CSPRNG-shaped byte stream backed by a blake2b_256
/// counter mode.  For benchmarks only — we mark it CryptoRng because
/// the trait is a marker, but it is NOT a vetted crypto primitive.
struct DetRng {
    seed: [u8; 32],
    counter: u64,
    buf: [u8; 32],
    buf_pos: usize,
}

impl DetRng {
    fn seed(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0, buf: [0u8; 32], buf_pos: 32 }
    }

    fn refill(&mut self) {
        use blake2::digest::{Update, VariableOutput};
        let mut h = blake2::Blake2bVar::new(32).unwrap();
        h.update(&self.seed);
        h.update(&self.counter.to_le_bytes());
        h.finalize_variable(&mut self.buf).unwrap();
        self.counter = self.counter.wrapping_add(1);
        self.buf_pos = 0;
    }
}

impl rand_core::RngCore for DetRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i < dest.len() {
            if self.buf_pos == 32 { self.refill(); }
            let take = (32 - self.buf_pos).min(dest.len() - i);
            dest[i..i + take].copy_from_slice(&self.buf[self.buf_pos..self.buf_pos + take]);
            self.buf_pos += take;
            i += take;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> StdResult<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for DetRng {}
