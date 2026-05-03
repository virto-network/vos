//! Real-workload validation actor: builds cipher-clerk Account values
//! and feeds their bytes into a running accumulator.  Exercises the
//! cipher-clerk types module, which depends on common no_std crates
//! (rkyv derives, etc.) — a representative slice of what a real
//! kernel-side cipher-clerk circuit would do.
//!
//! NOTE: this currently triggers a constraint failure in zkpvm related
//! to memory accesses against `.rodata` static data (see commit
//! message for the validation that lands the test as `#[ignore]`).

#![no_std]
#![no_main]

extern crate alloc;
use core::alloc::{GlobalAlloc, Layout};

struct NullAlloc;
unsafe impl GlobalAlloc for NullAlloc {
    unsafe fn alloc(&self, _l: Layout) -> *mut u8 { core::ptr::null_mut() }
    unsafe fn dealloc(&self, _p: *mut u8, _l: Layout) {}
}
#[global_allocator]
static ALLOC: NullAlloc = NullAlloc;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }

use cipher_clerk::ids::{AccountId, JournalId};
use cipher_clerk::types::Account;
use cipher_clerk::types::flags::Direction;
use cipher_clerk::crypto::sig::AuthKey;

#[inline(never)]
fn build_account(seed: u64) -> Account {
    let mut id_bytes = [0u8; 16];
    id_bytes[0..8].copy_from_slice(&seed.to_le_bytes());
    id_bytes[8..16].copy_from_slice(&seed.wrapping_mul(0xDEAD_BEEF_CAFE_BABE).to_le_bytes());
    let mut auth_bytes = [0u8; 32];
    auth_bytes[0..8].copy_from_slice(&seed.to_le_bytes());
    Account::new(
        AccountId(id_bytes),
        JournalId([1u8; 16]),
        AuthKey(auth_bytes),
        1u32,
        2u16,
        Direction::Credit,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut acc: u64 = 0;
    let mut i: u64 = 0;
    while i < 8 {
        let a = build_account(i.wrapping_mul(0x1234_5678_9ABC_DEF0));
        for b in a.id.0.iter() {
            acc = acc.wrapping_add(*b as u64).rotate_left(7);
        }
        acc = acc.wrapping_add(a.code as u64);
        acc = acc.wrapping_add(a.timestamp);
        i += 1;
    }
    core::hint::black_box(acc);
    unsafe { core::arch::asm!("unimp") }
    loop {}
}
