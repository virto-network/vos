//! Blake2b precompile — guest shim for `ECALL_BLAKE2B_COMPRESS`.
//!
//! `blake2b_compress`: one compression per call.  On riscv64 dispatches
//! to the ECALL; off-target falls through to the bundled software
//! reference (matches `zkpvm::chips::blake2b::compress` byte-for-byte).
//!
//! `blake2b_hash::<N>(domain, parts)`: streaming hash producing an
//! N-byte digest (1..=64).  Matches the `blake2` crate's
//! `Blake2b<UN>::default()` for any N.
//!
//! Self-contained — no curve25519-dalek dep — so a guest that only
//! needs hashing can build with `default-features = false, features
//! = ["blake2b"]`.

#[cfg(target_arch = "riscv64")]
use crate::ecalls::{ECALL_BLAKE2B_COMPRESS, VOS_OBJECT_CAP};

const BLAKE2B_IV: [u64; 8] = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
];

/// One blake2b compression: in-place update of `h` (64 bytes = 8 u64
/// LE) by mixing in the message block `m` (128 bytes = 16 u64 LE)
/// with byte counter `t` and finalize flag `f`.  On PVM dispatches
/// to ECALL_BLAKE2B_COMPRESS; on host runs the reference.
pub fn blake2b_compress(h: &mut [u8; 64], m: &[u8; 128], t: u128, f: bool) {
    #[cfg(target_arch = "riscv64")]
    {
        compress_pvm(h, m, t, f);
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        compress_host(h, m, t, f);
    }
}

#[cfg(target_arch = "riscv64")]
fn compress_pvm(h: &mut [u8; 64], m: &[u8; 128], t: u128, f: bool) {
    let h_ptr = h.as_mut_ptr() as u64;
    let m_ptr = m.as_ptr() as u64;
    let t_low = t as u64;
    let f_flag: u64 = if f { 1 } else { 0 };
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") ECALL_BLAKE2B_COMPRESS as u64,
            in("a0") h_ptr,
            in("a1") m_ptr,
            in("a2") t_low,
            in("a3") f_flag,
            in("t2") f_flag, // φ[7] convention for f flag
            in("a4") 0u64,
            in("a5") VOS_OBJECT_CAP,
            options(nostack),
        );
    }
}

#[cfg(not(target_arch = "riscv64"))]
fn compress_host(h: &mut [u8; 64], m: &[u8; 128], t: u128, f: bool) {
    let mut h_words = [0u64; 8];
    for i in 0..8 {
        h_words[i] = u64::from_le_bytes(h[i*8..i*8+8].try_into().unwrap());
    }
    let mut m_words = [0u64; 16];
    for i in 0..16 {
        m_words[i] = u64::from_le_bytes(m[i*8..i*8+8].try_into().unwrap());
    }
    let result = compress_inner(&h_words, &m_words, t, f);
    for i in 0..8 {
        h[i*8..i*8+8].copy_from_slice(&result[i].to_le_bytes());
    }
}

#[cfg(not(target_arch = "riscv64"))]
fn compress_inner(h: &[u64; 8], m: &[u64; 16], t: u128, f: bool) -> [u64; 8] {
    const SIGMA: [[usize; 16]; 12] = [
        [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
        [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
        [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],
        [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
        [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],
        [2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
        [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],
        [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
        [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],
        [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
        [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
        [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
    ];
    fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, mx: u64, my: u64) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(mx);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(my);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if f { v[14] = !v[14]; }
    for round in 0..12 {
        let s = &SIGMA[round];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    let mut result = [0u64; 8];
    for i in 0..8 { result[i] = h[i] ^ v[i] ^ v[i + 8]; }
    result
}

/// High-level blake2b hash: produces an `OUT_LEN` byte digest of
/// `domain || parts.concat()`.  Drives the precompile's compression
/// per 128-byte block.  Matches the `blake2` crate's
/// `Blake2b<UN>::default()` for output length N (no key, fanout=1,
/// depth=1, leaf_length=0, ...).
pub fn blake2b_hash<const OUT_LEN: usize>(domain: &[u8], parts: &[&[u8]]) -> [u8; OUT_LEN] {
    assert!(OUT_LEN >= 1 && OUT_LEN <= 64);
    // Parameter block: byte0 = digest_length, byte2 = fanout(1), byte3 = depth(1).
    // h[0] = IV[0] XOR param_block[0..8].
    let mut param_lo: u64 = 0x0101_0000 | (OUT_LEN as u64);  // bytes [3]=1, [2]=1, [0]=N
    let mut h_words = BLAKE2B_IV;
    h_words[0] ^= param_lo;
    let _ = &mut param_lo; // suppress unused_mut

    let mut h = [0u8; 64];
    for i in 0..8 {
        h[i*8..i*8+8].copy_from_slice(&h_words[i].to_le_bytes());
    }

    let mut buf = [0u8; 128];
    let mut buf_len = 0usize;
    let mut t: u128 = 0;

    let feed = |bytes: &[u8],
                    buf: &mut [u8; 128],
                    buf_len: &mut usize,
                    h: &mut [u8; 64],
                    t: &mut u128| {
        let mut i = 0;
        while i < bytes.len() {
            // If the buffer is FULL and there's at least one more byte
            // remaining (so this isn't the final block), compress.
            if *buf_len == 128 {
                *t += 128;
                blake2b_compress(h, buf, *t, false);
                *buf_len = 0;
            }
            let take = (128 - *buf_len).min(bytes.len() - i);
            buf[*buf_len..*buf_len + take].copy_from_slice(&bytes[i..i+take]);
            *buf_len += take;
            i += take;
        }
    };

    feed(domain, &mut buf, &mut buf_len, &mut h, &mut t);
    for p in parts {
        feed(p, &mut buf, &mut buf_len, &mut h, &mut t);
    }

    // Final block: pad with zeros, set finalize flag.
    for i in buf_len..128 { buf[i] = 0; }
    t += buf_len as u128;
    blake2b_compress(&mut h, &buf, t, true);

    let mut out = [0u8; OUT_LEN];
    out.copy_from_slice(&h[..OUT_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2b_512_matches_blake2_crate() {
        use blake2::digest::{consts::U64, Digest};
        type Blake2b512 = blake2::Blake2b<U64>;

        let ours: [u8; 64] = blake2b_hash(b"", &[]);
        let mut h = Blake2b512::new();
        let theirs = h.finalize_reset();
        assert_eq!(&ours[..], &theirs[..], "empty input mismatch");

        let ours: [u8; 64] = blake2b_hash(b"cipher-clerk/test", &[b"hello world"]);
        let mut h = Blake2b512::new();
        h.update(b"cipher-clerk/test");
        h.update(b"hello world");
        let theirs = h.finalize();
        assert_eq!(&ours[..], &theirs[..], "single-block mismatch");

        let part1 = alloc::vec![0xa5u8; 100];
        let part2 = alloc::vec![0x5au8; 100];
        let part3 = alloc::vec![0x33u8; 100];
        let ours: [u8; 64] = blake2b_hash(b"DOMAIN", &[&part1, &part2, &part3]);
        let mut h = Blake2b512::new();
        h.update(b"DOMAIN");
        h.update(&part1);
        h.update(&part2);
        h.update(&part3);
        let theirs = h.finalize();
        assert_eq!(&ours[..], &theirs[..], "multi-block mismatch");
    }

    #[test]
    fn blake2b_256_matches_blake2_crate() {
        use blake2::digest::{consts::U32, Digest};
        type Blake2b256 = blake2::Blake2b<U32>;

        let ours: [u8; 32] = blake2b_hash(b"hash-test", &[b"a", b"b", b"c"]);
        let mut h = Blake2b256::new();
        h.update(b"hash-test");
        h.update(b"a"); h.update(b"b"); h.update(b"c");
        let theirs = h.finalize();
        assert_eq!(&ours[..], &theirs[..]);
    }

    #[test]
    fn blake2b_exactly_one_block_boundary() {
        // 128 bytes total → exactly one compression block.
        use blake2::digest::{consts::U64, Digest};
        type B = blake2::Blake2b<U64>;
        let data = alloc::vec![0x42u8; 128];
        let ours: [u8; 64] = blake2b_hash(b"", &[&data]);
        let mut h = B::new();
        h.update(&data);
        let theirs = h.finalize();
        assert_eq!(&ours[..], &theirs[..], "exactly-one-block mismatch");
    }
}
