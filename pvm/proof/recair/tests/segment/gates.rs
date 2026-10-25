//! The masking's soundness gates on the masked segment.

use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use vos_pvm_proof::format::ChannelKind;
use vos_pvm_proof::poseidon2::P2MerkleChannel;
use vos_pvm_recair::masked::MaskRng;

use crate::support::{IO, format, prove, small_format, verify};

/// The small kernel's run proved masked and verified, on the Poseidon2-M31
/// channel (the segment's) and on Blake2s (the device's): R1 in one attempt,
/// every chip at its floor at least, and a seeded proof reproduced.
#[test]
fn a_masked_segment_verifies_on_both_channels() {
    let format = format();
    let (proof, stats) = prove::<P2MerkleChannel>(&format, IO, MaskRng::Seeded(1)).unwrap();
    verify::<P2MerkleChannel>(&format, &proof).expect("verifies");
    assert_eq!(stats.attempts, 1);
    assert!(proof.log_sizes.iter().all(|&log_size| log_size >= 8));
    let (again, _) = prove::<P2MerkleChannel>(&format, IO, MaskRng::Seeded(1)).unwrap();
    assert_eq!(
        again.proof.stark_proof.commitments.0,
        proof.proof.stark_proof.commitments.0
    );

    let blake = small_format(ChannelKind::Blake2s, 6, 4);
    let (proof, _) = prove::<Blake2sMerkleChannel>(&blake, IO, MaskRng::Seeded(2)).unwrap();
    verify::<Blake2sMerkleChannel>(&blake, &proof).expect("verifies");
}
