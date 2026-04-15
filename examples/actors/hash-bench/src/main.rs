//! Hash benchmark — bare-metal PVM program (no VOS runtime).
//!
//! Computes N iterations of a hash chain + Merkle proof directly,
//! without actor framework overhead. Exits via trap.

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }

/// Simple hash round: XOR-fold with rotation.
#[inline(never)]
fn hash_round(state: &mut [u8; 32]) {
    let mut tmp = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        tmp[i] = state[i]
            .wrapping_add(state[(i + 7) % 32])
            .wrapping_mul(137)
            ^ state[(i + 13) % 32];
        i += 1;
    }
    *state = tmp;
}

/// Merkle membership: hash leaf with path siblings to get root.
#[inline(never)]
fn merkle_verify(leaf: &[u8; 32], siblings: &[[u8; 32]; 4], index: u32) -> [u8; 32] {
    let mut current = *leaf;
    let mut idx = index;
    let mut level = 0;
    while level < 4 {
        let mut pair = [0u8; 32];
        let mut i = 0;
        if idx & 1 == 0 {
            while i < 16 { pair[i] = current[i]; i += 1; }
            i = 0;
            while i < 16 { pair[16 + i] = siblings[level][i]; i += 1; }
        } else {
            while i < 16 { pair[i] = siblings[level][i]; i += 1; }
            i = 0;
            while i < 16 { pair[16 + i] = current[i]; i += 1; }
        }
        hash_round(&mut pair);
        current = pair;
        idx >>= 1;
        level += 1;
    }
    current
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Phase 1: Hash chain — 10 rounds
    let mut state = [42u8; 32];
    let mut i = 0u32;
    while i < 10 {
        hash_round(&mut state);
        i += 1;
    }

    // Phase 2: Merkle proof verification (4-level tree)
    let siblings = [
        [0xAAu8; 32],
        [0xBBu8; 32],
        [0xCCu8; 32],
        [0xDDu8; 32],
    ];
    let _root = merkle_verify(&state, &siblings, 5);

    // Exit via trap (no host calls needed)
    unsafe { core::arch::asm!("unimp") }
    loop {}
}
