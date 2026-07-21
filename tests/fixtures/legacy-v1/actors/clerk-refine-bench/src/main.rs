//! cipher-clerk refine-shape benchmark — vos actor that builds a
//! batch of cipher-clerk Transfers and computes their canonical
//! signing payloads (the rkyv archive a verifier reproduces, the
//! kernel's heaviest per-transfer serialization).
//!
//! Models the CPU cost an `apply_batch_refine` sub-actor pays per
//! batch.  Doesn't yet call `kernel::apply_batch` — that requires
//! pre-signed Transfers and an Oracle/LedgerState, deferred to the
//! per-privacy-level clerk-l0/l1/l2/l3 actors under crates/actors/.

use vos::prelude::*;
use cipher_clerk::ids::{AccountId, JournalId, TransferId, TxTemplateId, EntryId};
use cipher_clerk::types::{Account, Transfer};
use cipher_clerk::types::flags::{Direction, Layer};
use cipher_clerk::types::entry::Entry;
use cipher_clerk::crypto::sig::{AuthKey, Signature};
use cipher_clerk::crypto::commit::Amount;

const N_TRANSFERS: u8 = 10;

#[actor]
struct ClerkRefineBench;

#[messages]
impl ClerkRefineBench {
    fn new() -> Self {
        ClerkRefineBench
    }

    /// Auto-invoked by vos's on_start hook on cold start (see
    /// vos-macros: methods named `start` are wired as the
    /// lifecycle on_start handler).  Runs one refine-shape batch:
    /// 4 accounts + 10 transfers × 4 entries each, signing-payload
    /// archive + rolling hash.
    #[msg]
    async fn start(&self, _ctx: &mut Context<Self>) -> u64 {
        let journal_id = JournalId([7u8; 16]);

        let accounts: [Account; 4] = [
            build_account(1, journal_id),
            build_account(2, journal_id),
            build_account(3, journal_id),
            build_account(4, journal_id),
        ];

        let mut digest: u64 = 0;
        for a in &accounts {
            for b in a.id.0.iter() {
                digest = digest.wrapping_add(*b as u64).rotate_left(7);
            }
        }

        let mut i: u8 = 0;
        while i < N_TRANSFERS {
            let t = build_transfer(i, journal_id, &accounts);
            let payload = t.signing_payload();
            for &b in payload.iter() {
                digest = digest.wrapping_add(b as u64).rotate_left(11);
            }
            i += 1;
        }

        digest
    }
}

#[inline(never)]
fn build_account(seed: u8, journal_id: JournalId) -> Account {
    let mut id_bytes = [0u8; 16];
    id_bytes[0] = seed;
    let mut auth_bytes = [0u8; 32];
    auth_bytes[0] = seed.wrapping_mul(3);
    Account::new(
        AccountId(id_bytes),
        journal_id,
        AuthKey(auth_bytes),
        840u32,
        100u16,
        Direction::Credit,
    )
}

#[inline(never)]
fn build_transfer(seed: u8, journal_id: JournalId, accounts: &[Account; 4]) -> Transfer {
    let mut tid = [0u8; 16];
    tid[0] = seed;
    tid[1] = 0xAA;
    let transfer_id = TransferId(tid);
    let mut tmpl = [0u8; 16];
    tmpl[0] = 0xBB;
    let template_id = TxTemplateId(tmpl);
    let amount = Amount([seed.wrapping_mul(7); 32]);

    let entry = |idx: u8, account: &Account, dir: Direction| -> Entry {
        let mut eid = [0u8; 16];
        eid[0] = seed;
        eid[1] = idx;
        let id = EntryId(eid);
        match dir {
            Direction::Debit => Entry::debit(
                id, transfer_id, journal_id, account.id,
                Layer::Settled, amount, 840, 100,
            ),
            Direction::Credit => Entry::credit(
                id, transfer_id, journal_id, account.id,
                Layer::Settled, amount, 840, 100,
            ),
        }
    };

    let entries = alloc::vec![
        entry(0, &accounts[0], Direction::Debit),
        entry(1, &accounts[1], Direction::Credit),
        entry(2, &accounts[2], Direction::Debit),
        entry(3, &accounts[3], Direction::Credit),
    ];
    let signatures = alloc::vec![Signature::ZERO; 2];

    Transfer::new(transfer_id, journal_id, template_id, entries, signatures)
}
