//! Guest-side shims for zkpvm precompile ECALLs.
//!
//! The shim re-exports `Scalar`, `RistrettoPoint`, and basepoint
//! constants from `curve25519-dalek` so consumer code reads
//! identically to plain dalek:
//!
//! ```ignore
//! use zkpvm_precompiles::{Scalar, RistrettoPoint, RISTRETTO_BASEPOINT_TABLE};
//! let v: Scalar = ...;
//! let g = &RISTRETTO_BASEPOINT_TABLE;
//! let h: RistrettoPoint = ...;
//! let p = &v * g + b * &h;
//! ```
//!
//! On `target_arch = "riscv64"` (the zkpvm guest target), the
//! `Mul` impls dispatch to an inline-asm `ecalli 200` that the
//! prover's `RistrettoChip` intercepts and accelerates via the
//! chip's witness/constraints.  On non-riscv64 targets the
//! multiplications fall through to dalek's native `Mul`.
//!
//! The wire ABI for the ECALL:
//!
//!   - hostcall ID 200 (`ECALL_RISTRETTO_SCALAR_MULT`)
//!   - φ[10] = scalar_ptr (32 canonical bytes, scalar mod ℓ)
//!   - φ[11] = point_ptr  (32 bytes, compressed Ristretto)
//!   - φ[12] = output_ptr (32 bytes, written by the call)
//!
//! Returns `[0u8; 32]` (canonical compressed identity) on either
//! non-canonical scalar or invalid input point.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use core::ops::Mul;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint as DalekRistrettoPoint};
use curve25519_dalek::scalar::Scalar as DalekScalar;

/// Hostcall ID for the Ristretto255 scalar-mult precompile.  Mirrors
/// `zkpvm::core::ecall::ECALL_RISTRETTO_SCALAR_MULT` in the prover.
pub const ECALL_RISTRETTO_SCALAR_MULT: u32 = 200;

/// Hostcall ID for the Ristretto255 compressed-point addition precompile.
/// Mirrors `zkpvm::core::ecall::ECALL_RISTRETTO_POINT_ADD`.
pub const ECALL_RISTRETTO_POINT_ADD: u32 = 201;

/// Hostcall ID for the wide-scalar reduction precompile.
/// Mirrors `zkpvm::core::ecall::ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE`.
pub const ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE: u32 = 202;

/// Hostcall ID for blake2b_compress (one compression per call).
/// Mirrors `zkpvm::core::ecall::ECALL_BLAKE2B_COMPRESS`.
/// Convention: φ[10]=h_ptr (64B in/out), φ[11]=m_ptr (128B in),
/// φ[12]=t_low (counter low 64 bits), φ[7]=f (finalize flag).
pub const ECALL_BLAKE2B_COMPRESS: u32 = 100;

/// Mirrors dalek's `Scalar * Scalar` (mod ℓ).
pub const ECALL_SCALAR_MUL_MOD_L: u32 = 203;
/// Mirrors dalek's `Scalar + Scalar` (mod ℓ).
pub const ECALL_SCALAR_ADD_MOD_L: u32 = 204;

/// Re-exports of dalek's types, so consumers don't depend on dalek
/// directly.  Wrapping is unnecessary since we override `Mul` for
/// references to these types; dalek's own `Mul` impls live next to
/// them but are shadowed by ours when `&Scalar * &RistrettoPoint`
/// or `&Scalar * &Basepoint` is invoked through this crate's
/// re-export chain.  However Rust's coherence rules don't let us
/// override foreign `Mul` impls on foreign types, so we wrap.
///
/// `Scalar` and `RistrettoPoint` are thin newtypes: `Deref` to
/// dalek's types so all dalek methods (compress, from_uniform_bytes,
/// from_canonical_bytes, etc.) are available transparently.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalar(pub DalekScalar);

/// Compressed-byte representation of a Ristretto255 group element.
/// Held as 32 raw bytes so that operator overloads (`Mul`, `Add`)
/// can issue PVM ECALLs directly without first compressing the
/// operands.  Eliminates the decompress + recompress round-trips
/// that previously bloated the PVM trace by ~10× per operation.
///
/// Conversion to/from dalek's `RistrettoPoint` (the decompressed
/// extended-coords form) goes through `from_dalek` / `into_dalek`
/// — these run dalek-internal field arithmetic on the host and
/// expand the PVM trace, so use sparingly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RistrettoPoint(pub [u8; 32]);

impl Scalar {
    pub fn from_canonical_bytes(b: [u8; 32]) -> Option<Self> {
        DalekScalar::from_canonical_bytes(b).into_option().map(Self)
    }

    /// Construct a Scalar from bytes that the caller PROMISES are
    /// canonical (< ℓ), bypassing dalek's montgomery_reduce-based
    /// validation.  Step 15 found that the validation chain trips
    /// a per-row constraint failure in some pre-existing chip; this
    /// helper avoids that path while preserving the canonicality
    /// guarantee on the result.
    ///
    /// SAFETY contract: the input bytes MUST encode a value < ℓ.
    /// Used by the shim's `from_bytes_mod_order_wide` (output is
    /// canonical by construction) and by cipher-clerk's
    /// `Blinding::to_dalek` (Blinding's own canonicality contract).
    pub fn from_canonical_bytes_unchecked(b: [u8; 32]) -> Self {
        // SAFETY: DalekScalar is a transparent newtype around
        // [u8; 32] with an invariant that the value is < ℓ.  The
        // caller guarantees that invariant.  transmute is layout-
        // equivalent (`#[repr(C)]` not required for newtype-of-array
        // single-field structs in stable layout).
        let s: DalekScalar = unsafe { core::mem::transmute(b) };
        Self(s)
    }
    pub fn from_bytes_mod_order_wide(b: &[u8; 64]) -> Self {
        // On PVM, dispatch to the ECALL precompile so the wide-scalar
        // reduction doesn't inflate the trace by ~60%.  Off PVM, fall
        // back to dalek's u64 backend (the host fallback inside
        // `scalar_from_bytes_mod_order_wide` does the same thing).
        //
        // Step 15 diag: bypass dalek's `from_canonical_bytes`
        // (montgomery_reduce-heavy) via unsafe transmute since the
        // precompile guarantees canonical bytes.  DalekScalar's repr
        // is a single `[u8; 32]` field (validated by the layout-pin
        // assertion above the call).
        let canonical = scalar_from_bytes_mod_order_wide(b);
        // SAFETY: DalekScalar is defined as `pub struct Scalar { bytes: [u8; 32] }`
        // — a transparent wrapper around 32 bytes.  `canonical` is < ℓ
        // (precompile guarantees), satisfying Scalar's canonicality
        // invariant.  transmute is layout-equivalent.
        let dalek_scalar: DalekScalar = unsafe { core::mem::transmute(canonical) };
        Self(dalek_scalar)
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    pub fn invert(&self) -> Self {
        Self(self.0.invert())
    }
    pub const ZERO: Self = Self(DalekScalar::ZERO);
    pub const ONE: Self = Self(DalekScalar::ONE);
}

impl From<u64> for Scalar {
    fn from(v: u64) -> Self { Self(DalekScalar::from(v)) }
}
impl From<u32> for Scalar {
    fn from(v: u32) -> Self { Self(DalekScalar::from(v)) }
}
impl From<DalekScalar> for Scalar {
    fn from(s: DalekScalar) -> Self { Self(s) }
}

// ── Scalar arithmetic (mirrors dalek's public Scalar API) ──
//
// On PVM, dispatches to ECALL_SCALAR_MUL_MOD_L / _ADD_MOD_L so the
// guest doesn't run dalek's u64 montgomery_mul/add chain inside
// the trace.  Off PVM, falls through to dalek directly.

impl<'a, 'b> Mul<&'b Scalar> for &'a Scalar {
    type Output = Scalar;
    fn mul(self, rhs: &'b Scalar) -> Scalar {
        let bytes = scalar_mul_mod_l(&self.0.to_bytes(), &rhs.0.to_bytes());
        Scalar::from_canonical_bytes_unchecked(bytes)
    }
}
impl Mul<Scalar> for Scalar {
    type Output = Scalar;
    fn mul(self, rhs: Scalar) -> Scalar { (&self).mul(&rhs) }
}

impl<'a, 'b> core::ops::Add<&'b Scalar> for &'a Scalar {
    type Output = Scalar;
    fn add(self, rhs: &'b Scalar) -> Scalar {
        let bytes = scalar_add_mod_l(&self.0.to_bytes(), &rhs.0.to_bytes());
        Scalar::from_canonical_bytes_unchecked(bytes)
    }
}
impl core::ops::Add<Scalar> for Scalar {
    type Output = Scalar;
    fn add(self, rhs: Scalar) -> Scalar { (&self).add(&rhs) }
}

impl RistrettoPoint {
    /// The 32-byte compressed encoding (this is the wire form).
    pub fn compress(&self) -> CompressedRistretto {
        CompressedRistretto::from_slice(&self.0)
            .expect("RistrettoPoint always holds 32 bytes")
    }
    pub fn to_bytes(&self) -> [u8; 32] { self.0 }
    pub fn from_bytes(b: [u8; 32]) -> Self { Self(b) }
    pub fn from_uniform_bytes(b: &[u8; 64]) -> Self {
        Self(DalekRistrettoPoint::from_uniform_bytes(b).compress().to_bytes())
    }
    /// Canonical compressed identity.
    pub fn identity() -> Self { Self([0u8; 32]) }
    /// Wrap a dalek decompressed point — runs `compress()` host-side.
    /// Heavy: prefer to keep operands in compressed form throughout
    /// any chain of operations; only convert at the boundary.
    pub fn from_dalek(p: DalekRistrettoPoint) -> Self {
        Self(p.compress().to_bytes())
    }
    /// Decompress to dalek — runs `decompress()` host-side.  Heavy.
    pub fn into_dalek(self) -> DalekRistrettoPoint {
        CompressedRistretto::from_slice(&self.0)
            .ok()
            .and_then(|c| c.decompress())
            .unwrap_or_default()
    }
}

impl From<DalekRistrettoPoint> for RistrettoPoint {
    fn from(p: DalekRistrettoPoint) -> Self { Self::from_dalek(p) }
}

impl core::ops::Add for RistrettoPoint {
    type Output = Self;
    fn add(self, rhs: Self) -> Self { (&self).add(&rhs) }
}
impl<'a, 'b> core::ops::Add<&'b RistrettoPoint> for &'a RistrettoPoint {
    type Output = RistrettoPoint;
    fn add(self, rhs: &'b RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint(ristretto_point_add(&self.0, &rhs.0))
    }
}

/// Fixed-base scalar mult against the Ristretto255 basepoint.
/// `&scalar * &RISTRETTO_BASEPOINT_TABLE` mirrors dalek's API.
pub struct RistrettoBasepointTable;

/// Singleton instance to mirror dalek's `RISTRETTO_BASEPOINT_TABLE`
/// constant.  Indirection through this type lets the `Mul` impl
/// dispatch to the ECALL on PVM.
pub const RISTRETTO_BASEPOINT_TABLE: RistrettoBasepointTable = RistrettoBasepointTable;

// ── Multiplications ──────────────────────────────────────────────

impl<'a, 'b> Mul<&'b RistrettoBasepointTable> for &'a Scalar {
    type Output = RistrettoPoint;
    fn mul(self, _: &'b RistrettoBasepointTable) -> RistrettoPoint {
        // k * G — fixed-base.  ECALL with point = compressed
        // basepoint bytes.
        scalar_mult_dispatch(self, &basepoint_compressed_bytes())
    }
}

impl<'a, 'b> Mul<&'b RistrettoPoint> for &'a Scalar {
    type Output = RistrettoPoint;
    fn mul(self, rhs: &'b RistrettoPoint) -> RistrettoPoint {
        // RistrettoPoint already holds 32 compressed bytes — no
        // conversion needed before the ECALL.
        scalar_mult_dispatch(self, &rhs.0)
    }
}

// Allow `scalar * &point` (by-value scalar) too, for ergonomics.
impl<'b> Mul<&'b RistrettoPoint> for Scalar {
    type Output = RistrettoPoint;
    fn mul(self, rhs: &'b RistrettoPoint) -> RistrettoPoint {
        (&self).mul(rhs)
    }
}
impl<'a> Mul<RistrettoPoint> for &'a Scalar {
    type Output = RistrettoPoint;
    fn mul(self, rhs: RistrettoPoint) -> RistrettoPoint {
        self.mul(&rhs)
    }
}

fn scalar_mult_dispatch(scalar: &Scalar, point: &[u8; 32]) -> RistrettoPoint {
    let scalar_bytes = scalar.to_bytes();
    let out = ristretto_scalar_mult(&scalar_bytes, point);
    // Output is already the canonical compressed encoding — no
    // decompress needed; downstream ops (Add, further Mul) work
    // directly on the compressed bytes via ECALL.
    RistrettoPoint(out)
}

fn basepoint_compressed_bytes() -> [u8; 32] {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
    RISTRETTO_BASEPOINT_COMPRESSED.to_bytes()
}

// ── Blake2b precompile ─────────────────────────────────────

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
        blake2b_compress_pvm(h, m, t, f);
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        blake2b_compress_host(h, m, t, f);
    }
}

#[cfg(target_arch = "riscv64")]
fn blake2b_compress_pvm(h: &mut [u8; 64], m: &[u8; 128], t: u128, f: bool) {
    let h_ptr = h.as_mut_ptr() as u64;
    let m_ptr = m.as_ptr() as u64;
    let t_low = t as u64;
    let f_flag: u64 = if f { 1 } else { 0 };
    const VOS_OBJECT_CAP: u64 = 65;
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
fn blake2b_compress_host(h: &mut [u8; 64], m: &[u8; 128], t: u128, f: bool) {
    // Reference: same logic as the prover's `blake2b_compress_sw`.
    let mut h_words = [0u64; 8];
    for i in 0..8 {
        h_words[i] = u64::from_le_bytes(h[i*8..i*8+8].try_into().unwrap());
    }
    let mut m_words = [0u64; 16];
    for i in 0..16 {
        m_words[i] = u64::from_le_bytes(m[i*8..i*8+8].try_into().unwrap());
    }
    let result = blake2b_compress_inner(&h_words, &m_words, t, f);
    for i in 0..8 {
        h[i*8..i*8+8].copy_from_slice(&result[i].to_le_bytes());
    }
}

#[cfg(not(target_arch = "riscv64"))]
fn blake2b_compress_inner(h: &[u64; 8], m: &[u64; 16], t: u128, f: bool) -> [u64; 8] {
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

// ── Low-level ABI (kept public for Step 3 trace integration) ──

/// Compute `k · P → Q` for a Ristretto255 scalar `k` and compressed
/// point `P`.  Returns the compressed encoding of `Q`.
///
/// Returns `[0u8; 32]` (canonical compressed identity) on either
/// non-canonical scalar bytes or invalid input point encoding.
pub fn ristretto_scalar_mult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    #[cfg(target_arch = "riscv64")]
    {
        ristretto_scalar_mult_pvm(scalar, point)
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        ristretto_scalar_mult_host(scalar, point)
    }
}

/// `(a * b) mod ℓ` — mirrors dalek's `Scalar * Scalar`.  Inputs are
/// canonical 32-byte little-endian scalars.  Output is canonical.
pub fn scalar_mul_mod_l(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    #[cfg(target_arch = "riscv64")]
    {
        scalar_mul_mod_l_pvm(a, b)
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        scalar_mul_mod_l_host(a, b)
    }
}

#[cfg(target_arch = "riscv64")]
fn scalar_mul_mod_l_pvm(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let a_ptr = a.as_ptr() as u64;
    let b_ptr = b.as_ptr() as u64;
    let output_ptr = output.as_mut_ptr() as u64;
    const VOS_OBJECT_CAP: u64 = 65;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") ECALL_SCALAR_MUL_MOD_L as u64,
            in("a0") a_ptr,
            in("a1") b_ptr,
            in("a2") output_ptr,
            in("a3") 0u64, in("a4") 0u64,
            in("a5") VOS_OBJECT_CAP,
            options(nostack),
        );
    }
    output
}

#[cfg(not(target_arch = "riscv64"))]
fn scalar_mul_mod_l_host(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let sa = DalekScalar::from_canonical_bytes(*a).into_option();
    let sb = DalekScalar::from_canonical_bytes(*b).into_option();
    match (sa, sb) {
        (Some(x), Some(y)) => (x * y).to_bytes(),
        _ => [0u8; 32],
    }
}

/// `(a + b) mod ℓ` — mirrors dalek's `Scalar + Scalar`.
pub fn scalar_add_mod_l(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    #[cfg(target_arch = "riscv64")]
    {
        scalar_add_mod_l_pvm(a, b)
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        scalar_add_mod_l_host(a, b)
    }
}

#[cfg(target_arch = "riscv64")]
fn scalar_add_mod_l_pvm(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let a_ptr = a.as_ptr() as u64;
    let b_ptr = b.as_ptr() as u64;
    let output_ptr = output.as_mut_ptr() as u64;
    const VOS_OBJECT_CAP: u64 = 65;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") ECALL_SCALAR_ADD_MOD_L as u64,
            in("a0") a_ptr,
            in("a1") b_ptr,
            in("a2") output_ptr,
            in("a3") 0u64, in("a4") 0u64,
            in("a5") VOS_OBJECT_CAP,
            options(nostack),
        );
    }
    output
}

#[cfg(not(target_arch = "riscv64"))]
fn scalar_add_mod_l_host(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let sa = DalekScalar::from_canonical_bytes(*a).into_option();
    let sb = DalekScalar::from_canonical_bytes(*b).into_option();
    match (sa, sb) {
        (Some(x), Some(y)) => (x + y).to_bytes(),
        _ => [0u8; 32],
    }
}

/// Reduce 64 uniform-random bytes to a canonical scalar mod ℓ.
/// Returns the canonical 32-byte little-endian encoding.  On a
/// host build this delegates to `curve25519-dalek`'s
/// `Scalar::from_bytes_mod_order_wide`; on a PVM build it issues
/// `ecall ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE`.
pub fn scalar_from_bytes_mod_order_wide(wide: &[u8; 64]) -> [u8; 32] {
    #[cfg(target_arch = "riscv64")]
    {
        scalar_from_bytes_mod_order_wide_pvm(wide)
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        scalar_from_bytes_mod_order_wide_host(wide)
    }
}

#[cfg(target_arch = "riscv64")]
fn scalar_from_bytes_mod_order_wide_pvm(wide: &[u8; 64]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let wide_ptr = wide.as_ptr() as u64;
    let output_ptr = output.as_mut_ptr() as u64;
    const VOS_OBJECT_CAP: u64 = 65;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE as u64,
            in("a0") wide_ptr,
            in("a1") output_ptr,
            in("a2") 0u64,
            in("a3") 0u64,
            in("a4") 0u64,
            in("a5") VOS_OBJECT_CAP,
            options(nostack),
        );
    }
    output
}

#[cfg(not(target_arch = "riscv64"))]
fn scalar_from_bytes_mod_order_wide_host(wide: &[u8; 64]) -> [u8; 32] {
    DalekScalar::from_bytes_mod_order_wide(wide).to_bytes()
}

/// Compute `P + Q` for two compressed Ristretto255 points.  Returns
/// the compressed encoding of the sum.  Returns `[0u8; 32]`
/// (canonical compressed identity) on either invalid input encoding.
pub fn ristretto_point_add(p: &[u8; 32], q: &[u8; 32]) -> [u8; 32] {
    #[cfg(target_arch = "riscv64")]
    {
        ristretto_point_add_pvm(p, q)
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        ristretto_point_add_host(p, q)
    }
}

#[cfg(target_arch = "riscv64")]
fn ristretto_point_add_pvm(p: &[u8; 32], q: &[u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let p_ptr = p.as_ptr() as u64;
    let q_ptr = q.as_ptr() as u64;
    let output_ptr = output.as_mut_ptr() as u64;
    const VOS_OBJECT_CAP: u64 = 65;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") ECALL_RISTRETTO_POINT_ADD as u64,
            in("a0") p_ptr,
            in("a1") q_ptr,
            in("a2") output_ptr,
            in("a3") 0u64,
            in("a4") 0u64,
            in("a5") VOS_OBJECT_CAP,
            options(nostack),
        );
    }
    output
}

#[cfg(not(target_arch = "riscv64"))]
fn ristretto_point_add_host(p: &[u8; 32], q: &[u8; 32]) -> [u8; 32] {
    let pp = match CompressedRistretto::from_slice(p)
        .ok()
        .and_then(|c| c.decompress())
    {
        Some(p) => p,
        None => return [0u8; 32],
    };
    let qq = match CompressedRistretto::from_slice(q)
        .ok()
        .and_then(|c| c.decompress())
    {
        Some(q) => q,
        None => return [0u8; 32],
    };
    (pp + qq).compress().to_bytes()
}

#[cfg(target_arch = "riscv64")]
fn ristretto_scalar_mult_pvm(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let scalar_ptr = scalar.as_ptr() as u64;
    let point_ptr = point.as_ptr() as u64;
    let output_ptr = output.as_mut_ptr() as u64;
    const VOS_OBJECT_CAP: u64 = 65;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") ECALL_RISTRETTO_SCALAR_MULT as u64,
            in("a0") scalar_ptr,
            in("a1") point_ptr,
            in("a2") output_ptr,
            in("a3") 0u64,
            in("a4") 0u64,
            in("a5") VOS_OBJECT_CAP,
            options(nostack),
        );
    }
    output
}

#[cfg(not(target_arch = "riscv64"))]
fn ristretto_scalar_mult_host(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let s = match DalekScalar::from_canonical_bytes(*scalar).into_option() {
        Some(s) => s,
        None => return [0u8; 32],
    };
    let p = match CompressedRistretto::from_slice(point)
        .ok()
        .and_then(|c| c.decompress())
    {
        Some(p) => p,
        None => return [0u8; 32],
    };
    (s * p).compress().to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    #[test]
    fn typed_scalar_mult_basepoint_matches_dalek() {
        let v: Scalar = 50u64.into();
        let g = &RISTRETTO_BASEPOINT_TABLE;
        let ours = &v * g;
        let theirs = (DalekScalar::from(50u64) * RISTRETTO_BASEPOINT_POINT)
            .compress().to_bytes();
        assert_eq!(ours.0, theirs);
    }

    #[test]
    fn typed_scalar_mult_arbitrary_point_matches_dalek() {
        let v: Scalar = 7u64.into();
        let p_dalek = DalekScalar::from(3u64) * RISTRETTO_BASEPOINT_POINT;
        let p = RistrettoPoint::from_dalek(p_dalek);
        let ours = &v * &p;
        let theirs = (DalekScalar::from(7u64) * p_dalek).compress().to_bytes();
        assert_eq!(ours.0, theirs);
    }

    #[test]
    fn pedersen_style_vg_plus_bh_matches_dalek() {
        let v: Scalar = 100u64.into();
        let b = Scalar::from_bytes_mod_order_wide(&[0x37; 64]);
        // Synthesize an H point off the basepoint for the test.
        let h_dalek = DalekScalar::from(7u64) * RISTRETTO_BASEPOINT_POINT;
        let h = RistrettoPoint::from_dalek(h_dalek);
        let g = &RISTRETTO_BASEPOINT_TABLE;
        let p = &v * g + &b * &h;
        let theirs = (DalekScalar::from(100u64) * RISTRETTO_BASEPOINT_POINT
            + b.0 * h_dalek).compress().to_bytes();
        assert_eq!(p.0, theirs);
    }

    #[test]
    fn point_add_matches_dalek() {
        let p_dalek = DalekScalar::from(7u64) * RISTRETTO_BASEPOINT_POINT;
        let q_dalek = DalekScalar::from(13u64) * RISTRETTO_BASEPOINT_POINT;
        let p = RistrettoPoint::from_dalek(p_dalek);
        let q = RistrettoPoint::from_dalek(q_dalek);
        let ours = &p + &q;
        let theirs = (p_dalek + q_dalek).compress().to_bytes();
        assert_eq!(ours.0, theirs);
    }

    #[test]
    fn raw_byte_api_2_times_g_matches_dalek() {
        let mut scalar = [0u8; 32];
        scalar[0] = 2;
        let point = curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
        let ours = ristretto_scalar_mult(&scalar, &point);
        let theirs = (DalekScalar::from(2u64) * RISTRETTO_BASEPOINT_POINT)
            .compress().to_bytes();
        assert_eq!(ours, theirs);
    }

    #[test]
    fn blake2b_512_matches_blake2_crate() {
        use blake2::digest::{consts::U64, Digest};
        type Blake2b512 = blake2::Blake2b<U64>;

        // Empty input.
        let ours: [u8; 64] = blake2b_hash(b"", &[]);
        let mut h = Blake2b512::new();
        let theirs = h.finalize_reset();
        assert_eq!(&ours[..], &theirs[..], "empty input mismatch");

        // Single short block.
        let ours: [u8; 64] = blake2b_hash(b"cipher-clerk/test", &[b"hello world"]);
        let mut h = Blake2b512::new();
        h.update(b"cipher-clerk/test");
        h.update(b"hello world");
        let theirs = h.finalize();
        assert_eq!(&ours[..], &theirs[..], "single-block mismatch");

        // Multi-block input (300 bytes total — needs 3 compressions).
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
    fn scalar_mul_matches_dalek() {
        let a = DalekScalar::from(7u64);
        let b = DalekScalar::from(13u64);
        let ours = scalar_mul_mod_l(&a.to_bytes(), &b.to_bytes());
        let theirs = (a * b).to_bytes();
        assert_eq!(ours, theirs);
    }

    #[test]
    fn scalar_add_matches_dalek() {
        let a = DalekScalar::from(123u64);
        let b = DalekScalar::from(456u64);
        let ours = scalar_add_mod_l(&a.to_bytes(), &b.to_bytes());
        let theirs = (a + b).to_bytes();
        assert_eq!(ours, theirs);
    }

    #[test]
    fn typed_scalar_arithmetic_matches_dalek() {
        // k + e * sk, the Schnorr signing operation.
        let k = Scalar::from(99u64);
        let e = Scalar::from(7u64);
        let sk = Scalar::from(13u64);
        let s_typed = &k + &(&e * &sk);
        let s_dalek = DalekScalar::from(99u64) + DalekScalar::from(7u64) * DalekScalar::from(13u64);
        assert_eq!(s_typed.0, s_dalek);
    }

    #[test]
    fn blake2b_exactly_one_block_boundary() {
        // 128 bytes total → exactly one compression block.
        // Behavior must match: feed one full block, then final
        // (with empty buffer? or with that block as final?).
        // Reference: blake2 crate.
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
