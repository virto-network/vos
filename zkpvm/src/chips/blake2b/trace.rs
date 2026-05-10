//! Trace-generation helpers for the Blake2b chip.
//!
//! `GRow` captures all witness data for one G-function row (96 per
//! compression); `g_traced` runs the G-function and fills the row, and the
//! ancillary helpers compute nibble/carry witnesses used by the AIR.

use super::consts::IV;

/// A single G-function row with all intermediate witness data.
pub(super) struct GRow {
    pub a_in: [u8; 8],
    pub b_in: [u8; 8],
    pub c_in: [u8; 8],
    pub d_in: [u8; 8],
    pub mx: [u8; 8],
    pub my: [u8; 8],
    pub a1: [u8; 8],
    pub carry1: [u8; 8],
    pub and1: [u8; 8], // d & a1
    pub c1: [u8; 8],
    pub carry2: [u8; 8],
    pub and2: [u8; 8], // b & c1
    pub a_out: [u8; 8],
    pub carry3: [u8; 8],
    pub and3: [u8; 8], // d1 & a_out
    pub c_out: [u8; 8],
    pub carry4: [u8; 8],
    pub and4: [u8; 8], // b1 & c_out
    pub b_out: [u8; 8],
    pub rot63_carry: [u8; 8],
    /// d_out = (d1 ^ a_out) rotated right 16.  Materialised so the row-chain
    /// constraint can forward it into V_next[di].
    pub d_out: [u8; 8],
    // Hi nibbles for AND lookups.  AxHi/BxHi are the hi nibbles of the two AND
    // operands (in the byte ordering used by AndN); ResxHi is the hi nibble of
    // the AND result byte.  For And3/And4 the A-side input is a derived byte
    // (d1/b1), so AxHi is the hi nibble of that derived byte.
    pub and1_a_hi: [u8; 8],
    pub and1_b_hi: [u8; 8],
    pub and1_res_hi: [u8; 8],
    pub and2_a_hi: [u8; 8],
    pub and2_b_hi: [u8; 8],
    pub and2_res_hi: [u8; 8],
    pub and3_a_hi: [u8; 8],
    pub and3_b_hi: [u8; 8],
    pub and3_res_hi: [u8; 8],
    pub and4_a_hi: [u8; 8],
    pub and4_b_hi: [u8; 8],
    pub and4_res_hi: [u8; 8],
    /// Snapshot of v[0..16] as LE bytes at the START of this row's G-call.
    pub v: [[u8; 8]; 16],
    /// Full message m[0..16] (LE bytes) for the compression this row belongs
    /// to.  Replicated per row so the per-row Mx/My = M[sigma_idx] constraint
    /// can be local; inter-row equality keeps M constant inside a compression.
    pub m: [[u8; 8]; 16],
    /// Compression inputs, replicated across the 96 rows of this compression.
    pub h: [[u8; 8]; 8],
    pub t: [u8; 16],
    pub f: u8,
    pub t_hi: [u8; 16],
    pub and_t_lo: [u8; 8],
    pub and_t_hi: [u8; 8],
    pub and_t_lo_hi: [u8; 8],
    pub and_t_hi_hi: [u8; 8],
    // ── Output derivation, only non-zero at the last row of a compression
    pub output: [u8; 64],
    pub h_hi: [u8; 64],
    pub v_after_hi: [u8; 128],
    pub out_and1: [u8; 64],
    pub out_and1_hi: [u8; 64],
    pub out_xor1_hi: [u8; 64],
    pub out_and2: [u8; 64],
    pub out_and2_hi: [u8; 64],
    // ── ECALL memory-binding witnesses, constant across the 96 rows of a
    // compression; address columns only referenced at IsFirstOfCompression.
    pub h_ptr: [u8; 4],
    pub m_ptr: [u8; 4],
    pub call_ts: [u8; 8],
    pub h_rd_addr: [u8; 256],
    pub m_rd_addr: [u8; 512],
    pub h_wr_addr: [u8; 256],
}

/// Execute one G-function and capture all intermediate values.  `v_snapshot`
/// is the full v[0..16] state at the start of this G-call (LE bytes); the
/// row-chain constraint requires it in the trace.  `m_full` is the full 16-
/// slot message for the compression this row belongs to.  `call_h`, `call_t`
/// and `call_f` are the compression-level inputs replicated on every row
/// for the initial-state derivation.
pub(super) fn g_traced(
    v_snapshot: &[u64; 16],
    m_full: &[u64; 16],
    call_h: &[u64; 8],
    call_t: u128,
    call_f: bool,
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    mx: u64,
    my: u64,
) -> GRow {
    let a_in = a.to_le_bytes();
    let b_in = b.to_le_bytes();
    let c_in = c.to_le_bytes();
    let d_in = d.to_le_bytes();
    let mx_b = mx.to_le_bytes();
    let my_b = my.to_le_bytes();

    // Step 1: a1 = a + b + mx
    let a1_val = a.wrapping_add(b).wrapping_add(mx);
    let a1 = a1_val.to_le_bytes();
    let carry1 = add_carry_chain(&a_in, &b_in, &mx_b);

    // Step 2: xor1 = d ^ a1, d1 = xor1 >>> 32 (byte swap)
    let xor1_val = d ^ a1_val;
    let and1 = byte_and(&d_in, &a1);
    let d1_val = xor1_val.rotate_right(32);

    // Step 3: c1 = c + d1
    let c1_val = c.wrapping_add(d1_val);
    let c1 = c1_val.to_le_bytes();
    let d1_bytes = d1_val.to_le_bytes();
    let carry2 = add_carry_chain_2(&c_in, &d1_bytes);

    // Step 4: xor2 = b ^ c1, b1 = xor2 >>> 24
    let xor2_val = b ^ c1_val;
    let and2 = byte_and(&b_in, &c1);
    let b1_val = xor2_val.rotate_right(24);

    // Step 5: a_out = a1 + b1 + my
    let a_out_val = a1_val.wrapping_add(b1_val).wrapping_add(my);
    let a_out = a_out_val.to_le_bytes();
    let b1_bytes = b1_val.to_le_bytes();
    let carry3 = add_carry_chain(&a1, &b1_bytes, &my_b);

    // Step 6: xor3 = d1 ^ a_out, d_out = xor3 >>> 16
    let xor3_val = d1_val ^ a_out_val;
    let and3 = byte_and(&d1_bytes, &a_out);
    let d_out_val = xor3_val.rotate_right(16);

    // Step 7: c_out = c1 + d_out
    let c_out_val = c1_val.wrapping_add(d_out_val);
    let c_out = c_out_val.to_le_bytes();
    let d_out_bytes = d_out_val.to_le_bytes();
    let carry4 = add_carry_chain_2(&c1, &d_out_bytes);

    // Step 8: xor4 = b1 ^ c_out, b_out = xor4 >>> 63
    let xor4_val = b1_val ^ c_out_val;
    let and4 = byte_and(&b1_bytes, &c_out);
    let b_out_val = xor4_val.rotate_right(63);
    let b_out = b_out_val.to_le_bytes();
    let rot63_carry = rot63_carries(&xor4_val.to_le_bytes());

    // Hi nibbles for AND lookups.
    let and1_a_hi = hi_nibbles(&d_in);
    let and1_b_hi = hi_nibbles(&a1);
    let and1_res_hi = hi_nibbles(&and1);
    let and2_a_hi = hi_nibbles(&b_in);
    let and2_b_hi = hi_nibbles(&c1);
    let and2_res_hi = hi_nibbles(&and2);
    let and3_a_hi = hi_nibbles(&d1_bytes); // derived: d1 = (d_in ^ a1) >>> 32
    let and3_b_hi = hi_nibbles(&a_out);
    let and3_res_hi = hi_nibbles(&and3);
    let and4_a_hi = hi_nibbles(&b1_bytes); // derived: b1 = (b_in ^ c1) >>> 24
    let and4_b_hi = hi_nibbles(&c_out);
    let and4_res_hi = hi_nibbles(&and4);

    let d_out = d_out_val.to_le_bytes();

    let mut v_bytes = [[0u8; 8]; 16];
    for k in 0..16 {
        v_bytes[k] = v_snapshot[k].to_le_bytes();
    }
    let mut m_bytes = [[0u8; 8]; 16];
    for k in 0..16 {
        m_bytes[k] = m_full[k].to_le_bytes();
    }
    let mut h_bytes = [[0u8; 8]; 8];
    for k in 0..8 {
        h_bytes[k] = call_h[k].to_le_bytes();
    }
    let t_bytes = call_t.to_le_bytes();
    let mut t_hi_bytes = [0u8; 16];
    for i in 0..16 {
        t_hi_bytes[i] = t_bytes[i] >> 4;
    }
    let mut and_t_lo = [0u8; 8];
    let mut and_t_hi = [0u8; 8];
    for i in 0..8 {
        and_t_lo[i] = IV[4].to_le_bytes()[i] & t_bytes[i];
        and_t_hi[i] = IV[5].to_le_bytes()[i] & t_bytes[8 + i];
    }
    let mut and_t_lo_hi = [0u8; 8];
    let mut and_t_hi_hi = [0u8; 8];
    for i in 0..8 {
        and_t_lo_hi[i] = and_t_lo[i] >> 4;
        and_t_hi_hi[i] = and_t_hi[i] >> 4;
    }

    GRow {
        a_in,
        b_in,
        c_in,
        d_in,
        mx: mx_b,
        my: my_b,
        a1,
        carry1,
        and1,
        c1,
        carry2,
        and2,
        a_out,
        carry3,
        and3,
        c_out,
        carry4,
        and4,
        b_out,
        rot63_carry,
        d_out,
        and1_a_hi,
        and1_b_hi,
        and1_res_hi,
        and2_a_hi,
        and2_b_hi,
        and2_res_hi,
        and3_a_hi,
        and3_b_hi,
        and3_res_hi,
        and4_a_hi,
        and4_b_hi,
        and4_res_hi,
        v: v_bytes,
        m: m_bytes,
        h: h_bytes,
        t: t_bytes,
        f: call_f as u8,
        t_hi: t_hi_bytes,
        and_t_lo,
        and_t_hi,
        and_t_lo_hi,
        and_t_hi_hi,
        // Phase 2b witnesses are zero by default; the trace-gen loop fills
        // them on the last row of each compression.
        output: [0u8; 64],
        h_hi: [0u8; 64],
        v_after_hi: [0u8; 128],
        out_and1: [0u8; 64],
        out_and1_hi: [0u8; 64],
        out_xor1_hi: [0u8; 64],
        out_and2: [0u8; 64],
        out_and2_hi: [0u8; 64],
        // Phase 8b ECALL-binding witnesses — filled by the outer loop from
        // the matching blake2b_mem_op (or zero if none).  Address columns
        // are deterministic from HPtr/MPtr plus the byte offset.
        h_ptr: [0u8; 4],
        m_ptr: [0u8; 4],
        call_ts: [0u8; 8],
        h_rd_addr: [0u8; 256],
        m_rd_addr: [0u8; 512],
        h_wr_addr: [0u8; 256],
    }
}

/// Derive v_after[0..16] at the final row of a compression (g_idx=7) from the
/// row's starting V plus the just-updated touched slots.  G_INDICES[7] =
/// [3, 4, 9, 14], so the a/b/c/d outputs land at those positions.
pub(super) fn row_v_after(r: &GRow) -> [[u8; 8]; 16] {
    let mut v_after = r.v;
    v_after[3] = r.a_out;
    v_after[4] = r.b_out;
    v_after[9] = r.c_out;
    v_after[14] = r.d_out;
    v_after
}

/// Fill the Phase 2b output-derivation witnesses on the last row of a
/// compression.  `v_after` is the v[0..16] state AFTER this row's G-call.
pub(super) fn fill_output_witnesses(row: &mut GRow, v_after: &[u64; 16]) {
    let mut v_after_bytes = [[0u8; 8]; 16];
    for k in 0..16 {
        v_after_bytes[k] = v_after[k].to_le_bytes();
    }

    for i in 0..8 {
        for j in 0..8 {
            let h_b = row.h[i][j];
            let v1 = v_after_bytes[i][j];
            let v2 = v_after_bytes[i + 8][j];
            let and1 = h_b & v1;
            let xor1 = h_b ^ v1;
            let and2 = xor1 & v2;
            let out = xor1 ^ v2;
            let slot = i * 8 + j;
            row.h_hi[slot] = h_b >> 4;
            row.out_and1[slot] = and1;
            row.out_and1_hi[slot] = and1 >> 4;
            row.out_xor1_hi[slot] = xor1 >> 4;
            row.out_and2[slot] = and2;
            row.out_and2_hi[slot] = and2 >> 4;
            row.output[slot] = out;
        }
    }
    for k in 0..16 {
        for j in 0..8 {
            row.v_after_hi[k * 8 + j] = v_after_bytes[k][j] >> 4;
        }
    }
}

fn hi_nibbles(bytes: &[u8; 8]) -> [u8; 8] {
    let mut r = [0u8; 8];
    for i in 0..8 {
        r[i] = bytes[i] >> 4;
    }
    r
}

fn byte_and(a: &[u8; 8], b: &[u8; 8]) -> [u8; 8] {
    let mut r = [0u8; 8];
    for i in 0..8 {
        r[i] = a[i] & b[i];
    }
    r
}

/// 3-input addition carry chain: a + b + c mod 2^64
fn add_carry_chain(a: &[u8; 8], b: &[u8; 8], c: &[u8; 8]) -> [u8; 8] {
    let mut carry = [0u8; 8];
    let mut c_val: u16 = 0;
    for i in 0..8 {
        let sum = a[i] as u16 + b[i] as u16 + c[i] as u16 + c_val;
        carry[i] = (sum >> 8) as u8;
        c_val = carry[i] as u16;
    }
    carry
}

/// 2-input addition carry chain: a + b mod 2^64
fn add_carry_chain_2(a: &[u8; 8], b: &[u8; 8]) -> [u8; 8] {
    let zero = [0u8; 8];
    add_carry_chain(a, b, &zero)
}

/// Carry bits for left-rotate-by-1 (= right-rotate by 63)
fn rot63_carries(input: &[u8; 8]) -> [u8; 8] {
    let mut carry = [0u8; 8];
    for i in 0..8 {
        carry[i] = input[i] >> 7;
    }
    carry
}
