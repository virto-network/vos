//! cipher-clerk refine-shape benchmark — runs the canonical
//! ledger sub-actor's hot CPU path directly in `_start`.
//!
//! This bench mirrors what a vos `apply_batch_refine` sub-actor does
//! per batch, minus the message-passing layer (vos needs a FETCH
//! invocation that the bare zkpvm test harness doesn't set up).
//! The cipher-clerk computation is identical:
//!
//!   1. Build N Account values (kernel state lookup hot path).
//!   2. Build N Transfer values with K entries each (the
//!      apply_batch input shape).
//!   3. Compute each transfer's `signing_payload` (the rkyv archive
//!      of the stripped TransferSigningView — Merkle leaf input,
//!      proof binding source, and the heaviest serialization the
//!      kernel does per transfer).
//!   4. Fold the bytes into a rolling hash so the workload can't
//!      be const-folded.
//!
//! Workload params: 10 transfers × 4 entries each = the typical
//! micro-batch size for a small-volume clerk under one JAM block.

#![no_std]
#![no_main]

extern crate alloc;
use core::alloc::{GlobalAlloc, Layout};

// Bump allocator backed by a static buffer.  cipher-clerk's
// signing_payload allocates a Vec; we need a real allocator.
use core::cell::UnsafeCell;

const HEAP_SIZE: usize = 64 * 1024;
struct BumpAlloc {
    heap: UnsafeCell<[u8; HEAP_SIZE]>,
    offset: UnsafeCell<usize>,
}
// PVM is singlethreaded — no atomics required.  Marking Sync for the
// global-allocator slot.
unsafe impl Sync for BumpAlloc {}

unsafe impl GlobalAlloc for BumpAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align();
        let size = layout.size();
        unsafe {
            let cur = *self.offset.get();
            let aligned = (cur + align - 1) & !(align - 1);
            let new_offset = aligned + size;
            if new_offset > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            *self.offset.get() = new_offset;
            (*self.heap.get()).as_mut_ptr().add(aligned)
        }
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOC: BumpAlloc = BumpAlloc {
    heap: UnsafeCell::new([0u8; HEAP_SIZE]),
    offset: UnsafeCell::new(0),
};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }

use cipher_clerk::ids::{AccountId, JournalId, TransferId, TxTemplateId, EntryId};
use cipher_clerk::types::{Account, Transfer};
use cipher_clerk::types::flags::{Direction, Layer};
use cipher_clerk::types::entry::Entry;
use cipher_clerk::crypto::sig::{AuthKey, Signature};
use cipher_clerk::crypto::commit::Amount;

const N_TRANSFERS: u8 = 10;

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
        840u32,             // ledger (USD per ISO-4217)
        100u16,             // code (asset class)
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

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let journal_id = JournalId([7u8; 16]);

    let accounts: [Account; 4] = [
        build_account(1, journal_id),
        build_account(2, journal_id),
        build_account(3, journal_id),
        build_account(4, journal_id),
    ];

    let mut digest: u64 = 0;
    // Touch every account's id bytes (kernel does this on
    // get_account → Merkle path verify).
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

    core::hint::black_box(digest);
    unsafe { core::arch::asm!("unimp") }
    loop {}
}
