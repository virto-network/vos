//! Poseidon2 precompile — guest shim for `ECALL_POSEIDON2`.
//!
//! `poseidon2_compress(left, right)`: the first eight words of the
//! Poseidon2-M31 width-16 permutation of `left ‖ right`, with no
//! feed-forward. On riscv64 it calls the precompile and, when the host
//! answers `WHAT` as a JAM node does, computes the same in software with
//! `vos-pvm-poseidon2`'s permutation; off-target it runs that permutation.
//!
//! Every word must be below p, on every host: the precompile traps a word at
//! or above it, and the software path panics, which traps the guest.

#[cfg(target_arch = "riscv64")]
use crate::ecalls::ECALL_POSEIDON2;

/// The Mersenne-31 modulus, `2^31 - 1`.
pub const P: u32 = vos_pvm_poseidon2::P;

/// The compression of two halves of eight M31 words.
///
/// # Panics
/// When a word is at or above p, as the precompile traps.
pub fn poseidon2_compress(left: &[u32; 8], right: &[u32; 8]) -> [u32; 8] {
    let mut input = [0u32; 16];
    input[..8].copy_from_slice(left);
    input[8..].copy_from_slice(right);
    poseidon2_compress_block(&input)
}

/// [`poseidon2_compress`] on the sixteen words the call reads, the guest's
/// own layout: the guest is little-endian, so the words' bytes are the
/// call's.
///
/// # Panics
/// When a word is at or above p.
pub fn poseidon2_compress_block(input: &[u32; 16]) -> [u32; 8] {
    let mut output = [0u32; 8];
    poseidon2_compress_into(input, &mut output);
    output
}

/// [`poseidon2_compress_block`] written to `output`, which the call writes
/// itself where a host serves it.
///
/// # Panics
/// When a word is at or above p.
pub fn poseidon2_compress_into(input: &[u32; 16], output: &mut [u32; 8]) {
    #[cfg(target_arch = "riscv64")]
    if crate::ecalls::call::<ECALL_POSEIDON2>(
        input.as_ptr() as u64,
        output.as_mut_ptr() as u64,
        0,
        0,
    ) {
        return;
    }
    let mut state = [vos_pvm_poseidon2::M31::ZERO; vos_pvm_poseidon2::N_STATE];
    for (word, &value) in state.iter_mut().zip(input) {
        // `M31::new` panics at or above p, as the call traps.
        *word = vos_pvm_poseidon2::M31::new(value);
    }
    vos_pvm_poseidon2::permute(&mut state);
    for (out, word) in output.iter_mut().zip(&state) {
        *out = word.value();
    }
}

/// [`poseidon2_compress_block`] refusing, rather than trapping on, a word at
/// or above p: `None` where the call would trap.
pub fn checked_poseidon2_compress_block(input: &[u32; 16]) -> Option<[u32; 8]> {
    input
        .iter()
        .all(|&word| word < P)
        .then(|| poseidon2_compress_block(input))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos_pvm_poseidon2::M31;

    #[test]
    fn the_shim_is_the_reference_compression() {
        let left: [u32; 8] = core::array::from_fn(|i| i as u32 * 0x1357_9bdf % P);
        let right: [u32; 8] = core::array::from_fn(|i| P - 1 - i as u32);
        let expected = vos_pvm_poseidon2::compress(&left.map(M31::new), &right.map(M31::new));
        assert_eq!(poseidon2_compress(&left, &right), expected.map(M31::value));
    }

    #[test]
    fn the_checked_compression_refuses_a_word_at_p() {
        let left: [u32; 8] = core::array::from_fn(|i| P - 1 - i as u32);
        let mut input: [u32; 16] = core::array::from_fn(|i| left[i % 8]);
        assert_eq!(
            checked_poseidon2_compress_block(&input),
            Some(poseidon2_compress(&left, &left))
        );
        input[15] = P;
        assert_eq!(checked_poseidon2_compress_block(&input), None);
    }

    #[test]
    #[should_panic(expected = "below p")]
    fn a_word_at_p_panics() {
        let mut right = [0u32; 8];
        right[7] = P;
        poseidon2_compress(&[0; 8], &right);
    }
}
