//! witnessed-transfer — the `#[provable]` W1 fixture: a **pure-verifier**
//! PVM guest whose traced execution proves a committed-map state
//! transition, built on [`vos::zk::state::WitnessedLedger`].
//!
//! ## What it proves
//!
//! A committed field of `u64 → u64` balances has a sparse-Merkle root.
//! The guest receives, in `__VOS_WITNESS`:
//!
//! - **public half** — the batch of transfers to apply (`(from, to,
//!   amount)` triples, flat little-endian);
//! - **secret half** — a [`LedgerWitness`]: the touched leaves (present
//!   content or proven-absent) plus a [`BatchProof`](vos::zk::state::BatchProof)
//!   over their keys, against an app-named `root_before`.
//!
//! It then:
//!
//! 1. builds a [`WitnessedLedger`] from the envelope — this *verifies*
//!    the touched leaves reconstruct `root_before` (every input, present
//!    or absent, bound in-circuit; a swapped value, a lying "absent", or
//!    a wrong root panics → `Trap` → the proof won't verify);
//! 2. applies each transfer against the witnessed balances (reads panic
//!    if unproven, an overdraft panics) and computes `root_after`;
//! 3. binds `(root_before, root_after, batch_digest)` into the proof's
//!    tagless io-hash. A verifier that independently knows `root_before`
//!    recomputes the same io-hash and checks it, composed with STARK
//!    validity against this program's commitment.
//!
//! **It writes no live storage.** A real deployment's invoking parent
//! applies the committed writes itself against the attested roots; the
//! Task only verifies and computes the transition. This is
//! cipher-clerk/voucher-check's `verify_transition`, generalized to the
//! framework SMT layer — the pattern W4 migrates voucher-check onto.
//!
//! ## Witness injection
//!
//! The host patches the length-prefixed `(public, secret)` payload into
//! `__VOS_WITNESS` (located by ELF symbol) before tracing. A bare run
//! with no injected witness is not a proving run; `start` returns early.

use vos::crypto::blake2b_hash;
use vos::prelude::*;
use vos::zk::state::{LedgerWitness, SmtParams};

// ZK witness-injection buffer. A `LedgerWitness` carries only the batch's
// TOUCHED leaves + their multiproof frontier (not the whole field), so
// its size scales with the batch, not the ledger.
vos::zk::witness_buffer!(16384);

/// Accounts are keyed by `u64` big-endian → an 8-byte key → a depth-64
/// SMT under the default vos domains.
const KEY_WIDTH: usize = 8;

/// Domain separating this fixture's batch digest from any other bytes.
const BATCH_DOMAIN: &[u8] = b"witnessed-transfer/batch/v1";

#[actor]
struct WitnessedTransfer;

#[messages]
impl WitnessedTransfer {
    fn new() -> Self {
        WitnessedTransfer
    }

    /// Lifecycle `on_start` hook — the prove path. Reads the witness,
    /// verifies + applies the transition, and binds the roots.
    #[msg]
    async fn start(&self, _ctx: &mut Context<Self>) -> u8 {
        let Some((public, secret)) = __vos_read_witness() else {
            // No injected witness — not a proving run. Nothing to prove.
            return 1;
        };

        // Public half: the batch of transfers.
        let transfers = decode_transfers(&public);

        // Secret half: the committed field's touched leaves + BatchProof.
        // A decode failure is a malformed witness → panic → Trap.
        let witness = vos::rkyv::from_bytes::<LedgerWitness, vos::rkyv::rancor::Error>(&secret)
            .expect("decode LedgerWitness from __VOS_WITNESS");
        let root_before = witness.root_before;

        // Verify the touched leaves reconstruct `root_before` (panics on
        // any inconsistency — swapped value, lying-absent, or wrong root).
        let mut ledger = witness.into_ledger(SmtParams::vos(KEY_WIDTH));

        // Apply the batch against the witnessed balances. Reads of an
        // unwitnessed account panic (unproven read); a proven-absent
        // account reads as zero balance. The sender is debited and
        // written BEFORE the recipient is read, so a self-transfer
        // (`to == from`) reads the already-debited balance and nets to a
        // no-op instead of minting; checked arithmetic traps overdraft
        // and overflow rather than wrapping.
        for &(from, to, amount) in &transfers {
            let from_key = from.to_be_bytes();
            let to_key = to.to_be_bytes();
            let from_bal = ledger.get(&from_key).map(decode_balance).unwrap_or(0);
            let debited = from_bal
                .checked_sub(amount)
                .unwrap_or_else(|| panic!("overdraft: account {from} has {from_bal} < {amount}"));
            ledger.insert(&from_key, debited.to_le_bytes().to_vec());
            let to_bal = ledger.get(&to_key).map(decode_balance).unwrap_or(0);
            let credited = to_bal
                .checked_add(amount)
                .unwrap_or_else(|| panic!("balance overflow crediting account {to}"));
            ledger.insert(&to_key, credited.to_le_bytes().to_vec());
        }
        let root_after = ledger.root();

        // Bind (root_before, root_after, batch_digest) as public inputs.
        // The batch digest ties the proven transition to THIS batch of
        // transfers (the public half), so an unrelated valid transition
        // can't be passed off as proving this one.
        let batch_digest = blake2b_hash::<32>(BATCH_DOMAIN, &[&public]);
        let mut public_bytes = Vec::with_capacity(96);
        public_bytes.extend_from_slice(&root_before);
        public_bytes.extend_from_slice(&root_after);
        public_bytes.extend_from_slice(&batch_digest);
        vos::zk::bind_io_bytes(&public_bytes, &[1u8]);
        1
    }
}

/// Decode an 8-byte little-endian balance leaf.
fn decode_balance(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().expect("8-byte balance leaf"))
}

/// Decode the public half: `[u32 count][ (from u64, to u64, amount u64) ×
/// count ]`, all little-endian. Panics on a truncated buffer.
fn decode_transfers(bytes: &[u8]) -> Vec<(u64, u64, u64)> {
    let count = u32::from_le_bytes(bytes[..4].try_into().expect("transfer count")) as usize;
    let mut out = Vec::with_capacity(count);
    let mut at = 4;
    let field = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("transfer field"));
    for _ in 0..count {
        let from = field(at);
        let to = field(at + 8);
        let amount = field(at + 16);
        at += 24;
        out.push((from, to, amount));
    }
    out
}
