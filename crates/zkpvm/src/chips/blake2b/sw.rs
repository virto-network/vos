//! Software reference implementation of the Blake2b compression function.
//! Used both by the prover-side trace generation (to derive v-state snapshots)
//! and as a public helper for tests that want to compute expected outputs.

use super::consts::{G_INDICES, IV, SIGMA};

pub fn blake2b_compress(h: &[u64; 8], m: &[u64; 16], t: u128, f: bool) -> [u64; 8] {
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if f { v[14] = !v[14]; }

    for round in 0..12 {
        let s = &SIGMA[round];
        for g_idx in 0..8 {
            let [ai, bi, ci, di] = G_INDICES[g_idx];
            let (mx_idx, my_idx) = (s[2 * g_idx], s[2 * g_idx + 1]);
            g_func(&mut v, ai, bi, ci, di, m[mx_idx], m[my_idx]);
        }
    }

    let mut result = [0u64; 8];
    for i in 0..8 { result[i] = h[i] ^ v[i] ^ v[i + 8]; }
    result
}

pub(super) fn g_func(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, mx: u64, my: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(mx);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(my);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}
