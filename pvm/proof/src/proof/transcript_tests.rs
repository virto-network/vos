//! The lossless boundary encoding and the interaction PoW.

use super::*;
use crate::format::{LEGACY_SEGMENT, SEGMENT};
use crate::framework_access::{
    AllLookupElements, boundary_relation_challenges, draw_all_lookup_elements,
};
use crate::poseidon2::Poseidon2M31Channel;
use stwo::core::fields::m31::{BaseField, P};

fn state(register: u64) -> SegmentState {
    let mut registers = [7u64; 13];
    registers[3] = register;
    SegmentState {
        pc: 0x1000,
        timestamp: 1,
        registers,
        memory_commitment: [0; 32],
        memory_root: [9; 32],
    }
}

/// The boundary relations' challenges, drawn after `initial` and
/// `final_state` are mixed as format 31 mixes them.
fn challenges(
    initial: &SegmentState,
    final_state: &SegmentState,
) -> [(SecureField, SecureField); 3] {
    let channel = &mut Poseidon2M31Channel::default();
    mix_boundary_states(channel, SEGMENT.encoding, initial, final_state);
    let mut lookups = AllLookupElements::default();
    draw_all_lookup_elements(&mut lookups, channel, u32::MAX);
    boundary_relation_challenges(&lookups)
}

/// Two boundary states apart only by p in one 32-bit word of a register
/// draw different challenges. The retired encoding, `reduce(lo32),
/// reduce(hi32)`, absorbed them alike.
#[test]
fn boundary_states_apart_by_p_in_a_word_draw_different_challenges() {
    let p = u64::from(P);
    let retired = |value: u64| {
        [
            BaseField::reduce(value & 0xffff_ffff),
            BaseField::reduce(value >> 32),
        ]
    };
    let end = state(0);
    for (low, high) in [(5, 5 + p), (5 << 32, (5 + p) << 32)] {
        assert_eq!(retired(low), retired(high), "the retired encoding collides");
        assert_ne!(
            challenges(&state(low), &end),
            challenges(&state(high), &end)
        );
        assert_ne!(
            challenges(&end, &state(low)),
            challenges(&end, &state(high))
        );
        let mixed = |value| {
            let mut channel = Poseidon2M31Channel::default();
            channel.mix_u64(value);
            channel.draw_secure_felt()
        };
        assert_ne!(mixed(low), mixed(high), "the channel's u64 mix");
    }
}

/// The lossless run absorbs the boundary chips' bytes: 296 of them, the
/// registers first, every one below 256.
#[test]
fn the_boundary_run_is_the_chips_bytes() {
    let bytes = crate::boundary_binding::boundary_state_bytes(&state(0x0102), &state(3));
    assert_eq!(bytes.len(), 296);
    assert_eq!(&bytes[24..32], &0x0102u64.to_le_bytes());
    assert_eq!(&bytes[208..212], &0x1000u32.to_le_bytes());
    assert_eq!(&bytes[264..296], &[9; 32]);
}

/// The interaction PoW: a ground nonce passes and is mixed, another
/// nonce is refused; a format without one takes only the nonce 0.
#[test]
fn the_interaction_pow_is_checked() {
    let mut channel = Poseidon2M31Channel::default();
    channel.mix_u64(1);
    let bits = SEGMENT.interaction_pow_bits();
    let nonce = (0u64..)
        .find(|&nonce| channel.verify_pow_nonce(bits, nonce))
        .unwrap();
    let wrong = (0u64..)
        .find(|&nonce| !channel.verify_pow_nonce(bits, nonce))
        .unwrap();
    assert!(check_interaction_pow(&mut channel.clone(), &SEGMENT, wrong).is_err());
    let mut mixed = channel.clone();
    check_interaction_pow(&mut mixed, &SEGMENT, nonce).unwrap();
    assert_ne!(
        mixed.clone().draw_secure_felt(),
        channel.clone().draw_secure_felt()
    );

    let mut legacy = channel.clone();
    check_interaction_pow(&mut legacy, &LEGACY_SEGMENT, 0).unwrap();
    assert_eq!(
        legacy.draw_secure_felt(),
        channel.clone().draw_secure_felt()
    );
    assert!(check_interaction_pow(&mut channel, &LEGACY_SEGMENT, nonce.max(1)).is_err());
}
