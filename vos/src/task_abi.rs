//! The witness-delivered Task input ABI — the unified input channel.
//!
//! A Task invocation delivers `(state, msg)` by patching the child's
//! initial memory image at its witness-buffer address — the same
//! `__VOS_WITNESS` channel the prover's tracer patches
//! (`zkpvm::actor::trace_blob_with_patches`), and the same shape as a
//! JAM work-package payload. The live invocation and a traced
//! re-execution therefore start from byte-identical images: proving a
//! recorded Task invocation is a literal replay of bytes the parent
//! already held.
//!
//! The child is FETCH-free and READ-free — refine-pure by construction
//! (`run_task_service` reads this buffer instead of issuing input
//! hostcalls), which is exactly what JAR refine permits for `machine`-
//! nested blobs.
//!
//! ## Layout (little-endian)
//!
//! ```text
//! [magic: u32 = TASK_INPUT_MAGIC][state_len: u32][state][msg_len: u32][msg]
//! [n_rows: u32] ( [key_len: u16][key][present: u8]([value_len: u32][value])? )*
//! ```
//!
//! The magic distinguishes a patched buffer from the all-zeros `.bss`
//! initial image (state may legitimately be empty on a first spawn, so
//! a leading length can't carry that signal). The trailing rows are
//! the **witnessed storage reads** — rows the host prefetched from the
//! invoking parent's effective keyspace because the caller named their
//! keys; the guest's storage handles read them through the witnessed
//! backend, which panics on any key the witness doesn't carry. A
//! rows-free input encodes `n_rows = 0` — four zero bytes, identical
//! to the `.bss` padding they overwrite, so pre-rows images are
//! byte-stable. The zk `(public, secret)` witness layout
//! (`crate::zk::read_witness_buffer`) is a different payload
//! convention over the same buffer — an actor decodes whichever layout
//! its invoker patched; the prover is layout-agnostic either way.

use alloc::vec::Vec;

/// Leading marker of a patched Task input buffer (`b"VOST"`, LE).
pub const TASK_INPUT_MAGIC: u32 = u32::from_le_bytes(*b"VOST");

/// Encode a Task invocation's `(state, msg)` for patching into the
/// child's witness buffer. Host-side counterpart of
/// [`read_task_input`]; also the exact bytes a prover replays.
pub fn encode_task_input(state: &[u8], msg: &[u8]) -> Vec<u8> {
    encode_task_input_with_rows(state, msg, &[])
}

/// [`encode_task_input`] plus the witnessed storage rows the child's
/// handles may read. `None` values are proven-absent rows — the caller
/// named the key and the parent keyspace holds nothing there, so a
/// witnessed read returns absent instead of panicking as unproven.
/// The prover replays these exact bytes, so a proven execution commits
/// to the rows it was fed — a doctored row set changes the emitted
/// anchor and fails the verifier's comparison.
pub fn encode_task_input_with_rows(
    state: &[u8],
    msg: &[u8],
    rows: &[(Vec<u8>, Option<Vec<u8>>)],
) -> Vec<u8> {
    let rows_len: usize = rows
        .iter()
        .map(|(k, v)| 7 + k.len() + v.as_ref().map_or(0, |v| v.len()))
        .sum();
    let mut out = Vec::with_capacity(16 + state.len() + msg.len() + rows_len);
    out.extend_from_slice(&TASK_INPUT_MAGIC.to_le_bytes());
    out.extend_from_slice(&(state.len() as u32).to_le_bytes());
    out.extend_from_slice(state);
    out.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    out.extend_from_slice(msg);
    out.extend_from_slice(&(rows.len() as u32).to_le_bytes());
    for (key, value) in rows {
        out.extend_from_slice(&(key.len() as u16).to_le_bytes());
        out.extend_from_slice(key);
        match value {
            Some(value) => {
                out.push(1);
                out.extend_from_slice(&(value.len() as u32).to_le_bytes());
                out.extend_from_slice(value);
            }
            None => out.push(0),
        }
    }
    out
}

/// Read a Task input back from a witness buffer of capacity `cap`
/// bytes at `ptr`. Returns `None` when the buffer is unpatched (no
/// magic) or malformed (a declared length runs past `cap`). Uses
/// volatile reads so a zero-initialised `.bss` buffer isn't optimised
/// away on the guest.
///
/// # Safety
/// `ptr` must point to at least `cap` readable bytes for the duration
/// of the call (satisfied by the macro-emitted `__VOS_WITNESS` static).
pub unsafe fn read_task_input(ptr: *const u8, cap: usize) -> Option<(Vec<u8>, Vec<u8>)> {
    let read_u32 = |off: usize| -> Option<u32> {
        if off.checked_add(4)? > cap {
            return None;
        }
        let mut bytes = [0u8; 4];
        for (i, b) in bytes.iter_mut().enumerate() {
            // SAFETY: bounds-checked against `cap` above; the caller
            // guarantees `cap` readable bytes at `ptr`.
            *b = unsafe { core::ptr::read_volatile(ptr.add(off + i)) };
        }
        Some(u32::from_le_bytes(bytes))
    };
    let read_bytes = |off: usize, len: usize| -> Option<Vec<u8>> {
        if off.checked_add(len)? > cap {
            return None;
        }
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            // SAFETY: bounds-checked against `cap` above.
            out.push(unsafe { core::ptr::read_volatile(ptr.add(off + i)) });
        }
        Some(out)
    };

    if read_u32(0)? != TASK_INPUT_MAGIC {
        return None;
    }
    let state_len = read_u32(4)? as usize;
    let state = read_bytes(8, state_len)?;
    let msg_off = 8 + state_len;
    let msg_len = read_u32(msg_off)? as usize;
    let msg = read_bytes(msg_off + 4, msg_len)?;
    Some((state, msg))
}

/// Read the witnessed storage rows trailing a Task input. Same safety
/// contract as [`read_task_input`]. Absent-or-zero `n_rows` (including
/// a pre-rows exact-fit buffer whose capacity ends at the message) is
/// an empty set; a declared length running past `cap` is malformed —
/// `None`, which the entry path treats like an unpatched buffer.
///
/// # Safety
/// `ptr` must point to at least `cap` readable bytes.
pub unsafe fn read_task_rows(
    ptr: *const u8,
    cap: usize,
) -> Option<Vec<(Vec<u8>, Option<Vec<u8>>)>> {
    let read_u16 = |off: usize| -> Option<u16> {
        if off.checked_add(2)? > cap {
            return None;
        }
        let mut bytes = [0u8; 2];
        for (i, b) in bytes.iter_mut().enumerate() {
            // SAFETY: bounds-checked against `cap` above.
            *b = unsafe { core::ptr::read_volatile(ptr.add(off + i)) };
        }
        Some(u16::from_le_bytes(bytes))
    };
    let read_u32 = |off: usize| -> Option<u32> {
        if off.checked_add(4)? > cap {
            return None;
        }
        let mut bytes = [0u8; 4];
        for (i, b) in bytes.iter_mut().enumerate() {
            // SAFETY: bounds-checked against `cap` above.
            *b = unsafe { core::ptr::read_volatile(ptr.add(off + i)) };
        }
        Some(u32::from_le_bytes(bytes))
    };
    let read_bytes = |off: usize, len: usize| -> Option<Vec<u8>> {
        if off.checked_add(len)? > cap {
            return None;
        }
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            // SAFETY: bounds-checked against `cap` above.
            out.push(unsafe { core::ptr::read_volatile(ptr.add(off + i)) });
        }
        Some(out)
    };

    if read_u32(0)? != TASK_INPUT_MAGIC {
        return None;
    }
    let state_len = read_u32(4)? as usize;
    let msg_off = 8usize.checked_add(state_len)?;
    let msg_len = read_u32(msg_off)? as usize;
    let mut off = msg_off.checked_add(4)?.checked_add(msg_len)?;
    // A pre-rows buffer sized exactly to its (state, msg) has no room
    // for the count — that is the empty set, not a malformed input.
    let Some(n_rows) = read_u32(off) else {
        return Some(Vec::new());
    };
    off += 4;
    let read_u8 = |off: usize| -> Option<u8> {
        if off.checked_add(1)? > cap {
            return None;
        }
        // SAFETY: bounds-checked against `cap` above.
        Some(unsafe { core::ptr::read_volatile(ptr.add(off)) })
    };
    let mut rows = Vec::with_capacity(n_rows as usize);
    for _ in 0..n_rows {
        let key_len = read_u16(off)? as usize;
        off += 2;
        let key = read_bytes(off, key_len)?;
        off += key_len;
        let present = read_u8(off)?;
        off += 1;
        let value = if present != 0 {
            let value_len = read_u32(off)? as usize;
            off += 4;
            let value = read_bytes(off, value_len)?;
            off += value_len;
            Some(value)
        } else {
            None
        };
        rows.push((key, value));
    }
    Some(rows)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_including_empty_state() {
        // Empty state is the first-spawn case — the magic (not a
        // leading length) is what distinguishes it from unpatched.
        for (state, msg) in [
            (&b""[..], &b"start"[..]),
            (&b"some-state"[..], &b"m"[..]),
            (&b"s"[..], &b""[..]),
        ] {
            let buf = encode_task_input(state, msg);
            let (s, m) = unsafe { read_task_input(buf.as_ptr(), buf.len()) }.expect("decodes");
            assert_eq!(s, state);
            assert_eq!(m, msg);
        }
    }

    #[test]
    fn unpatched_buffer_reads_none() {
        let zeros = [0u8; 64];
        assert!(unsafe { read_task_input(zeros.as_ptr(), zeros.len()) }.is_none());
        assert!(unsafe { read_task_rows(zeros.as_ptr(), zeros.len()) }.is_none());
    }

    #[test]
    fn rows_roundtrip_and_stay_byte_stable_when_empty() {
        // A rows-free encode appends four zero bytes — identical to
        // the .bss padding it overwrites, so pre-rows Task images stay
        // byte-stable (the live≡traced parity leans on this).
        let plain = encode_task_input(b"st", b"msg");
        assert_eq!(&plain[plain.len() - 4..], &[0u8; 4]);
        assert_eq!(
            unsafe { read_task_rows(plain.as_ptr(), plain.len()) }.expect("decodes"),
            Vec::new(),
        );
        // An exact-fit pre-rows buffer (capacity ends at the message)
        // decodes as the empty set, not malformed.
        let pre_rows = &plain[..plain.len() - 4];
        assert_eq!(
            unsafe { read_task_rows(pre_rows.as_ptr(), pre_rows.len()) }.expect("decodes"),
            Vec::new(),
        );

        let rows = vec![
            (b"s/tallies/vK".to_vec(), Some(b"forty-two".to_vec())),
            (b"present-empty".to_vec(), Some(Vec::new())),
            (b"proven-absent".to_vec(), None),
        ];
        let buf = encode_task_input_with_rows(b"st", b"msg", &rows);
        let (s, m) = unsafe { read_task_input(buf.as_ptr(), buf.len()) }.expect("input");
        assert_eq!((s.as_slice(), m.as_slice()), (&b"st"[..], &b"msg"[..]));
        assert_eq!(
            unsafe { read_task_rows(buf.as_ptr(), buf.len()) }.expect("rows"),
            rows,
        );
        // A truncated rows section is malformed, not empty.
        assert!(unsafe { read_task_rows(buf.as_ptr(), buf.len() - 1) }.is_none());
    }

    #[test]
    fn oversized_lengths_read_none() {
        let mut buf = encode_task_input(b"st", b"msg");
        // Declare a state length past the buffer.
        buf[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(unsafe { read_task_input(buf.as_ptr(), buf.len()) }.is_none());
    }
}
