//! An enrolled device's digests as the operator takes them: one code a
//! camera reads off the device's own chrome (a QR code of
//! [`enrollment_code`]), and a six-digit check both sides show
//! ([`enrollment_check`]), so no one reads 128 hexadecimal characters
//! aloud.
//!
//! The check catches a code misread, or read from the wrong screen. It
//! proves nothing of who chose the digests: six digits are found in about
//! a million tries. What the operator invites is what the device's chrome
//! showed, as ever.

use vos_pvm_precompiles::blake2b_hash;

/// The code's prefix.
pub const ENROLLMENT_CODE: &str = "VOSENROLL1:";

/// The check's domain.
const CHECK_DOMAIN: &[u8] = b"vos/enrollment/check/v1";

/// The member digest `member` and the owner digest `owner` as one code:
/// [`ENROLLMENT_CODE`] and upper-case hexadecimal of `member ‖ owner`, all
/// in a QR code's alphanumeric set.
pub fn enrollment_code(member: &[u8; 32], owner: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut code = String::with_capacity(ENROLLMENT_CODE.len() + 128);
    code.push_str(ENROLLMENT_CODE);
    for byte in member.iter().chain(owner) {
        code.push(HEX[usize::from(byte >> 4)] as char);
        code.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    code
}

/// The member and owner digests of an [`enrollment_code`], its hexadecimal
/// in either case; `None` for any other text.
pub fn read_enrollment_code(text: &str) -> Option<([u8; 32], [u8; 32])> {
    let digits = text.trim().strip_prefix(ENROLLMENT_CODE)?.as_bytes();
    if digits.len() != 128 {
        return None;
    }
    let nibble = |digit: u8| char::from(digit).to_digit(16).map(|value| value as u8);
    let mut bytes = [0u8; 64];
    for (byte, pair) in bytes.iter_mut().zip(digits.chunks_exact(2)) {
        *byte = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    let (member, owner) = bytes.split_at(32);
    Some((member.try_into().ok()?, owner.try_into().ok()?))
}

/// The six digits both sides show for `member` and `owner`, as `"123 456"`:
/// the first four bytes of `BLAKE2b-256("vos/enrollment/check/v1" ‖ member
/// ‖ owner)`, little-endian, modulo a million.
pub fn enrollment_check(member: &[u8; 32], owner: &[u8; 32]) -> String {
    let hash: [u8; 32] = blake2b_hash(CHECK_DOMAIN, &[member, owner]);
    let check = u32::from_le_bytes(hash[..4].try_into().expect("four bytes")) % 1_000_000;
    format!("{:03} {:03}", check / 1000, check % 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_reads_back_and_its_check_is_six_digits() {
        let (member, owner) = ([0xab; 32], [0x01; 32]);
        let code = enrollment_code(&member, &owner);
        assert_eq!(code.len(), ENROLLMENT_CODE.len() + 128);
        assert!(code.ends_with("0101"));
        assert_eq!(read_enrollment_code(&code), Some((member, owner)));
        let lower = format!(
            " {ENROLLMENT_CODE}{} ",
            code[ENROLLMENT_CODE.len()..].to_lowercase()
        );
        assert_eq!(read_enrollment_code(&lower), Some((member, owner)));
        assert_eq!(read_enrollment_code(&code[..code.len() - 1]), None);
        assert_eq!(read_enrollment_code(&code.replace('A', "G")), None);
        assert_eq!(read_enrollment_code("VOSHOME1:00"), None);
        let check = enrollment_check(&member, &owner);
        assert_eq!(check.len(), 7);
        assert!(check.chars().enumerate().all(|(i, c)| if i == 3 {
            c == ' '
        } else {
            c.is_ascii_digit()
        }));
        assert_ne!(
            check,
            enrollment_check(&owner, &member),
            "the digests' order counts"
        );
    }
}
