//! Hash benchmark — compares different hash algorithms on bare-metal PVM.
//!
//! Each hash runs a chain of N iterations, then a 4-level Merkle proof.
//! Select algorithm via the HASH constant.

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }

// ── Algorithm selection ──
// 0 = toy, 1 = Blake2s-inspired, 2 = SHA-256-like, 3 = Keccak-f[1600]
const HASH: u32 = 1;
const ROUNDS: u32 = 10;

// ═══════════════════════════════════════════════════════════════════
// Toy hash: XOR-fold with wrapping arithmetic (baseline)
// ═══════════════════════════════════════════════════════════════════
fn hash_toy(data: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = data[i]
            .wrapping_add(data[(i + 7) % 32])
            .wrapping_mul(137)
            ^ data[(i + 13) % 32];
        i += 1;
    }
    out
}

// ═══════════════════════════════════════════════════════════════════
// Blake2s-inspired: quarter-round mixing on 32-bit words
// (simplified — not full Blake2s, but exercises similar ops)
// ═══════════════════════════════════════════════════════════════════
fn load_u32_le(b: &[u8], off: usize) -> u32 {
    (b[off] as u32) | (b[off+1] as u32) << 8 | (b[off+2] as u32) << 16 | (b[off+3] as u32) << 24
}
fn store_u32_le(b: &mut [u8], off: usize, v: u32) {
    b[off] = v as u8; b[off+1] = (v >> 8) as u8; b[off+2] = (v >> 16) as u8; b[off+3] = (v >> 24) as u8;
}

fn hash_blake2s(data: &[u8; 32]) -> [u8; 32] {
    // Load 8 x u32 state words
    let mut v = [0u32; 8];
    let mut i = 0;
    while i < 8 { v[i] = load_u32_le(data, i * 4); i += 1; }

    // IV constants (first 8 primes' fractional parts)
    let iv: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];

    // Mix with IV
    i = 0;
    while i < 8 { v[i] = v[i].wrapping_add(iv[i]); i += 1; }

    // 4 quarter-rounds (simplified Blake2s G function)
    let mut round = 0;
    while round < 4 {
        // G(v[0], v[2], v[4], v[6])
        v[0] = v[0].wrapping_add(v[2]); v[6] ^= v[0]; v[6] = v[6].rotate_right(16);
        v[4] = v[4].wrapping_add(v[6]); v[2] ^= v[4]; v[2] = v[2].rotate_right(12);
        v[0] = v[0].wrapping_add(v[2]); v[6] ^= v[0]; v[6] = v[6].rotate_right(8);
        v[4] = v[4].wrapping_add(v[6]); v[2] ^= v[4]; v[2] = v[2].rotate_right(7);
        // G(v[1], v[3], v[5], v[7])
        v[1] = v[1].wrapping_add(v[3]); v[7] ^= v[1]; v[7] = v[7].rotate_right(16);
        v[5] = v[5].wrapping_add(v[7]); v[3] ^= v[5]; v[3] = v[3].rotate_right(12);
        v[1] = v[1].wrapping_add(v[3]); v[7] ^= v[1]; v[7] = v[7].rotate_right(8);
        v[5] = v[5].wrapping_add(v[7]); v[3] ^= v[5]; v[3] = v[3].rotate_right(7);
        round += 1;
    }

    // XOR with original state
    i = 0;
    while i < 8 { v[i] ^= load_u32_le(data, i * 4); i += 1; }

    let mut out = [0u8; 32];
    i = 0;
    while i < 8 { store_u32_le(&mut out, i * 4, v[i]); i += 1; }
    out
}

// ═══════════════════════════════════════════════════════════════════
// Keccak-f[1600]: real cryptographic permutation (from Nexus examples)
// Exercises: 64-bit XOR, rotate_left, NOT-AND, array indexing
// ═══════════════════════════════════════════════════════════════════
fn keccakf(st: &mut [u64; 25]) {
    const RNDC: [u64; 24] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ];
    const ROTC: [u32; 24] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];
    const PILN: [usize; 24] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];

    let mut r = 0;
    while r < 24 {
        let mut bc = [0u64; 5];
        let mut i = 0;
        while i < 5 { bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20]; i += 1; }
        i = 0;
        while i < 5 {
            let t = bc[(i+4) % 5] ^ bc[(i+1) % 5].rotate_left(1);
            let mut j = 0;
            while j < 25 { st[j+i] ^= t; j += 5; }
            i += 1;
        }
        let mut t = st[1];
        i = 0;
        while i < 24 {
            let j = PILN[i];
            bc[0] = st[j]; st[j] = t.rotate_left(ROTC[i]); t = bc[0];
            i += 1;
        }
        let mut j = 0;
        while j < 25 {
            i = 0;
            while i < 5 { bc[i] = st[j+i]; i += 1; }
            i = 0;
            while i < 5 { st[j+i] ^= (!bc[(i+1)%5]) & bc[(i+2)%5]; i += 1; }
            j += 5;
        }
        st[0] ^= RNDC[r];
        r += 1;
    }
}

fn hash_keccak(data: &[u8; 32]) -> [u8; 32] {
    let mut st = [0u64; 25];
    // Load 32 bytes into first 4 u64 words
    let mut i = 0;
    while i < 4 {
        st[i] = load_u32_le(data, i*8) as u64 | (load_u32_le(data, i*8+4) as u64) << 32;
        i += 1;
    }
    // Padding
    st[4] ^= 0x01; // delimiter
    st[16] ^= 0x8000000000000000; // last bit (rate = 136 bytes = 17 u64s)
    keccakf(&mut st);
    // Extract 32 bytes
    let mut out = [0u8; 32];
    i = 0;
    while i < 4 {
        store_u32_le(&mut out, i*8, st[i] as u32);
        store_u32_le(&mut out, i*8+4, (st[i] >> 32) as u32);
        i += 1;
    }
    out
}

// ═══════════════════════════════════════════════════════════════════
// SHA-256-like: operates on 32-bit words with shifts and rotates
// ═══════════════════════════════════════════════════════════════════
fn hash_sha256(data: &[u8; 32]) -> [u8; 32] {
    let mut w = [0u32; 8];
    let mut i = 0;
    while i < 8 { w[i] = load_u32_le(data, i * 4); i += 1; }

    let k: [u32; 8] = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    ];

    // 8 compression rounds (simplified)
    let mut round = 0;
    while round < 8 {
        let s1 = w[4].rotate_right(6) ^ w[4].rotate_right(11) ^ w[4].rotate_right(25);
        let ch = (w[4] & w[5]) ^ ((!w[4]) & w[6]);
        let temp1 = w[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(k[round]).wrapping_add(w[round]);
        let s0 = w[0].rotate_right(2) ^ w[0].rotate_right(13) ^ w[0].rotate_right(22);
        let maj = (w[0] & w[1]) ^ (w[0] & w[2]) ^ (w[1] & w[2]);
        let temp2 = s0.wrapping_add(maj);

        w[7] = w[6]; w[6] = w[5]; w[5] = w[4];
        w[4] = w[3].wrapping_add(temp1);
        w[3] = w[2]; w[2] = w[1]; w[1] = w[0];
        w[0] = temp1.wrapping_add(temp2);
        round += 1;
    }

    // Final XOR
    i = 0;
    while i < 8 { w[i] ^= load_u32_le(data, i * 4); i += 1; }

    let mut out = [0u8; 32];
    i = 0;
    while i < 8 { store_u32_le(&mut out, i * 4, w[i]); i += 1; }
    out
}

// ═══════════════════════════════════════════════════════════════════

#[inline(never)]
fn hash(data: &[u8; 32]) -> [u8; 32] {
    match HASH {
        0 => hash_toy(data),
        1 => hash_blake2s(data),
        2 => hash_sha256(data),
        3 => hash_keccak(data),
        _ => hash_toy(data),
    }
}

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
        current = hash(&pair);
        idx >>= 1;
        level += 1;
    }
    current
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut state = [42u8; 32];
    let mut i = 0u32;
    while i < ROUNDS {
        state = hash(&state);
        i += 1;
    }

    let siblings = [[0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32], [0xDDu8; 32]];
    let _root = merkle_verify(&state, &siblings, 5);

    unsafe { core::arch::asm!("unimp") }
    loop {}
}
