//! The Gray Paper's skip function (v0.8.0 `pvm.tex`, eq. skip): the one
//! definition the interpreter, the predecoder, the JIT, the gas model and
//! the proof tracer share.

/// The cap on skip: the most argument bytes an instruction is read with.
pub const SKIP_MAX: usize = 24;

const ONES: u64 = 0x0101_0101_0101_0101;

/// `skip(i) = min(24, j : (k ++ [1, 1, ...])_{i+1+j} = 1)`: how many bytes
/// follow the opcode at `i` before the next instruction's opcode, read from
/// the instruction-start mask `bitmask` (one byte per code byte, `1` at an
/// opcode; the mask continues with ones past its end).
///
/// Reads eight mask bytes at a time as a little-endian word, so mask byte
/// `n` of a window is the word's byte `n` on every target, and the first
/// set byte is the word's lowest. A window holding a byte other than 0 or
/// 1, and the mask's last partial window, are read byte by byte.
#[inline(always)]
pub fn skip(bitmask: &[u8], i: usize) -> usize {
    let start = i + 1;
    let mut j = 0;
    while j < SKIP_MAX {
        let Some(window) = bitmask.get(start + j..).and_then(<[u8]>::first_chunk::<8>) else {
            break;
        };
        let word = u64::from_le_bytes(*window);
        if word & !ONES != 0 {
            break;
        }
        if word != 0 {
            return j + (word.trailing_zeros() / 8) as usize;
        }
        j += 8;
    }
    skip_scalar(bitmask, start, j)
}

/// `skip` from the `from`-th byte after the opcode on, one byte at a time.
#[inline(always)]
fn skip_scalar(bitmask: &[u8], start: usize, from: usize) -> usize {
    (from..SKIP_MAX)
        .find(|&j| bitmask.get(start + j).is_none_or(|&bit| bit == 1))
        .unwrap_or(SKIP_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// The equation as written: the mask extended with ones, the least `j`
    /// that hits a one, capped at 24.
    fn oracle(k: &[u8], i: usize) -> usize {
        let extended = |n: usize| if n < k.len() { k[n] } else { 1 };
        let j = (0..).find(|&j| extended(i + 1 + j) == 1).unwrap();
        core::cmp::min(24, j)
    }

    fn agree(mask: &[u8]) {
        for i in 0..mask.len() + 3 {
            let expected = oracle(mask, i);
            assert_eq!(skip(mask, i), expected, "skip at {i} of {mask:?}");
            assert_eq!(
                skip_scalar(mask, i + 1, 0),
                expected,
                "scalar at {i} of {mask:?}"
            );
        }
    }

    #[test]
    fn every_mask_up_to_twelve_bytes() {
        for len in 0..=12 {
            for bits in 0u32..1 << len {
                let mask: Vec<u8> = (0..len).map(|n| ((bits >> n) & 1) as u8).collect();
                agree(&mask);
            }
        }
    }

    /// One start (or none) in a zero mask: every distance to the next
    /// start, across the word boundaries and past the cap, up to the end
    /// of the mask.
    #[test]
    fn every_zero_run_and_end_of_code() {
        for len in 0..=64 {
            agree(&vec![0; len]);
            for at in 0..len {
                let mut mask = vec![0; len];
                mask[at] = 1;
                agree(&mask);
            }
        }
    }

    /// The same masks read from every alignment of the underlying buffer.
    #[test]
    fn every_alignment() {
        for offset in 0..8 {
            for gap in [0, 6, 7, 8, 9, 15, 16, 17, 22, 23, 24, 25, 26, 40] {
                let mut buffer = vec![1; offset];
                buffer.push(1);
                buffer.extend(core::iter::repeat_n(0, gap));
                buffer.extend([1, 0, 0]);
                agree(&buffer[offset..]);
            }
        }
    }

    /// Bytes other than 0 and 1 are not instruction starts.
    #[test]
    fn only_a_one_is_a_start() {
        let values = [0, 1, 2, 3, 0x80, 0x81, 0xFE, 0xFF];
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..4096 {
            let len = (next() % 48) as usize;
            let mask: Vec<u8> = (0..len).map(|_| values[(next() % 8) as usize]).collect();
            agree(&mask);
        }
    }
}
