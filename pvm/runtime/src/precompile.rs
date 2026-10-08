//! VOS precompiles: deterministic memory transforms a guest invokes with
//! `ecalli` and the node serves natively.
//!
//! Precompile ids live in `0x400..=0x4ff`, outside every id JAM assigns
//! (the Gray Paper host calls and JIP-1 `log` at 100). A JAM node answers an
//! unknown id with `WHAT` in φ[7] and continues, so a guest that falls back
//! to software on `WHAT` computes identical results everywhere. A precompile
//! leaves every register unchanged; φ[7] holds an input pointer, never
//! `WHAT`, so the guest can tell the two apart.
//!
//! The refine host serves precompiles in place, inside the current machine
//! slice, for the outer machine and for inner machines alike, and reports
//! each call so a proof tracer can attach the matching chip rows.

/// One BLAKE2b compression: φ[7] = h pointer (64 bytes, read and written),
/// φ[8] = m pointer (128 bytes, read), φ[9] = counter low 64 bits,
/// φ[10] = finalize flag (non-zero = last block).
pub const BLAKE2B_COMPRESS: u64 = 0x400;

/// Whether `id` names a precompile the refine host serves in place.
pub const fn is_precompile(id: u64) -> bool {
    id == BLAKE2B_COMPRESS
}

/// The inputs and output of one served precompile call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrecompileCall {
    Blake2bCompress {
        h_ptr: u32,
        m_ptr: u32,
        h: [u64; 8],
        m: [u64; 16],
        t: u128,
        f: bool,
        h_bytes: [u8; 64],
        m_bytes: [u8; 128],
        out_bytes: [u8; 64],
    },
}

/// Serve precompile `id` against `memory` with `registers` as its
/// arguments. `None` means an argument range was not accessible; the
/// caller turns that into a guest panic, as for any host call.
pub fn execute(
    id: u64,
    registers: &[u64; crate::PVM_REGISTER_COUNT],
    memory: &mut crate::interpreter::Memory,
) -> Option<PrecompileCall> {
    match id {
        BLAKE2B_COMPRESS => blake2b_compress(registers, memory),
        _ => None,
    }
}

fn blake2b_compress(
    registers: &[u64; crate::PVM_REGISTER_COUNT],
    memory: &mut crate::interpreter::Memory,
) -> Option<PrecompileCall> {
    let h_ptr = u32::try_from(registers[7]).ok()?;
    let m_ptr = u32::try_from(registers[8]).ok()?;
    let t = u128::from(registers[9]);
    let f = registers[10] != 0;
    let mut h_bytes = [0u8; 64];
    let mut m_bytes = [0u8; 128];
    if !memory.read_bytes_checked(h_ptr, &mut h_bytes)
        || !memory.read_bytes_checked(m_ptr, &mut m_bytes)
    {
        return None;
    }
    let mut h = [0u64; 8];
    let mut m = [0u64; 16];
    for (i, word) in h.iter_mut().enumerate() {
        *word = u64::from_le_bytes(h_bytes[i * 8..i * 8 + 8].try_into().unwrap());
    }
    for (i, word) in m.iter_mut().enumerate() {
        *word = u64::from_le_bytes(m_bytes[i * 8..i * 8 + 8].try_into().unwrap());
    }
    let result = compress(&h, &m, t, f);
    let mut out_bytes = [0u8; 64];
    for (i, word) in result.iter().enumerate() {
        out_bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    if !memory.write_bytes_checked(h_ptr, &out_bytes) {
        return None;
    }
    Some(PrecompileCall::Blake2bCompress {
        h_ptr,
        m_ptr,
        h,
        m,
        t,
        f,
        h_bytes,
        m_bytes,
        out_bytes,
    })
}

const IV: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// The BLAKE2b compression function F (RFC 7693, section 3.2).
pub fn compress(h: &[u64; 8], m: &[u64; 16], t: u128, f: bool) -> [u64; 8] {
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if f {
        v[14] = !v[14];
    }
    for s in &SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    let mut out = [0u64; 8];
    for i in 0..8 {
        out[i] = h[i] ^ v[i] ^ v[i + 8];
    }
    out
}

fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}
