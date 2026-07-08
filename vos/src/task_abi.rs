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
//! ```
//!
//! The magic distinguishes a patched buffer from the all-zeros `.bss`
//! initial image (state may legitimately be empty on a first spawn, so
//! a leading length can't carry that signal). The zk `(public, secret)`
//! witness layout (`crate::zk::read_witness_buffer`) is a different
//! payload convention over the same buffer — an actor decodes whichever
//! layout its invoker patched; the prover is layout-agnostic either way.

use alloc::vec::Vec;

/// Leading marker of a patched Task input buffer (`b"VOST"`, LE).
pub const TASK_INPUT_MAGIC: u32 = u32::from_le_bytes(*b"VOST");

/// Encode a Task invocation's `(state, msg)` for patching into the
/// child's witness buffer. Host-side counterpart of
/// [`read_task_input`]; also the exact bytes a prover replays.
pub fn encode_task_input(state: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + state.len() + msg.len());
    out.extend_from_slice(&TASK_INPUT_MAGIC.to_le_bytes());
    out.extend_from_slice(&(state.len() as u32).to_le_bytes());
    out.extend_from_slice(state);
    out.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    out.extend_from_slice(msg);
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
    }

    #[test]
    fn oversized_lengths_read_none() {
        let mut buf = encode_task_input(b"st", b"msg");
        // Declare a state length past the buffer.
        buf[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(unsafe { read_task_input(buf.as_ptr(), buf.len()) }.is_none());
    }
}
