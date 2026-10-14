//! Byte comparison a word at a time. Under the Gray Paper's pipeline gas
//! model a load costs 25 cycles, so the byte loop compiler_builtins provides
//! costs about fifty gas a byte, and keys are compared on every lookup.
//! [`crate::program_runtime!`] exports this as `memcmp` and `bcmp`.

/// Compare `len` bytes at `a` and `b` as `memcmp` does: words while both
/// sides share an alignment, as heap allocations do, and bytes otherwise.
///
/// # Safety
///
/// Both ranges must be readable for `len` bytes.
#[inline]
pub unsafe fn compare(a: *const u8, b: *const u8, len: usize) -> i32 {
    const WORD: usize = core::mem::size_of::<u64>();
    let mut at = 0;
    if (a as usize ^ b as usize).is_multiple_of(WORD) {
        while at < len && !(a as usize + at).is_multiple_of(WORD) {
            // SAFETY: `at < len`.
            let (x, y) = unsafe { (*a.add(at), *b.add(at)) };
            if x != y {
                return i32::from(x) - i32::from(y);
            }
            at += 1;
        }
        while at + WORD <= len {
            // SAFETY: both sides are word-aligned here and `at + WORD <= len`.
            let (x, y) = unsafe { (*a.add(at).cast::<u64>(), *b.add(at).cast::<u64>()) };
            if x != y {
                // Read in memory order, the lowest differing byte is the
                // first.
                let (x, y) = (u64::from_le(x), u64::from_le(y));
                let shift = (x ^ y).trailing_zeros() & !7;
                return i32::from((x >> shift) as u8) - i32::from((y >> shift) as u8);
            }
            at += WORD;
        }
    }
    while at < len {
        // SAFETY: `at < len`.
        let (x, y) = unsafe { (*a.add(at), *b.add(at)) };
        if x != y {
            return i32::from(x) - i32::from(y);
        }
        at += 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::compare;

    #[test]
    fn agrees_with_slice_order_at_every_alignment_and_length() {
        let base: Vec<u8> = (0..64u8).map(|byte| byte.wrapping_mul(37)).collect();
        for shift in 0..9 {
            for len in 0..40 {
                for flip in 0..len {
                    let mut other = base.clone();
                    other[shift + flip] ^= 0x80;
                    let (a, b) = (&base[shift..shift + len], &other[shift..shift + len]);
                    // SAFETY: both slices hold `len` bytes.
                    let ordering = unsafe { compare(a.as_ptr(), b.as_ptr(), len) };
                    assert_eq!(
                        ordering.signum(),
                        a.cmp(b) as i32,
                        "shift {shift} len {len}"
                    );
                    // SAFETY: as above.
                    assert_eq!(unsafe { compare(a.as_ptr(), a.as_ptr(), len) }, 0);
                }
            }
        }
        let shifted = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        // SAFETY: nine bytes each.
        let ordering = unsafe { compare(shifted.as_ptr(), shifted[1..].as_ptr(), 9) };
        assert!(ordering < 0, "different alignments compare bytewise");
    }
}
