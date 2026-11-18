//! The golden device proof `device_verify_mutate` mutates: an honest proof
//! of `device_program`'s kernel, kept in `device-golden.proof` (its io-hash,
//! then the proof's bytes) so each input is replayed against the same
//! proof. The seed (`cargo run --example seed`) writes it anew when the
//! program no longer accepts it; a target refuses to start on one it does
//! not accept.

#![allow(dead_code)]

use std::sync::OnceLock;

use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleHasher;
use vos_pvm_device::{decode, encode, MaskedProof, Refusal, Verifier, FORMAT};

use crate::device_program;

/// Where the golden is kept.
pub const FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/device-golden.proof");

/// The most nonces a ground proof tries: a nonce passes the 8-bit
/// interaction PoW at 2^-8, so a commitment set that passes none of them
/// comes once in about e^16.
const GRIND: u64 = 1 << 12;

pub struct DeviceGolden {
    /// The io-hash the kernel states.
    pub io: [u8; 32],
    /// The proof's bytes, its one encoding.
    pub proof: Vec<u8>,
    pub verifier: Verifier,
}

/// The golden, read once and checked: the program accepts it, and its
/// decode re-encodes to its bytes.
pub fn golden() -> &'static DeviceGolden {
    static GOLDEN: OnceLock<DeviceGolden> = OnceLock::new();
    GOLDEN.get_or_init(|| {
        let bytes = std::fs::read(FILE).unwrap_or_else(|error| panic!("{FILE}: {error}"));
        let (io, proof) = bytes
            .split_first_chunk::<32>()
            .unwrap_or_else(|| panic!("{FILE}: shorter than an io-hash"));
        let golden = DeviceGolden {
            io: *io,
            proof: proof.to_vec(),
            verifier: device_program::program().verifier(),
        };
        assert!(
            golden.verifier.verify(&golden.io, &golden.proof).is_ok(),
            "{FILE} is not accepted: `cargo run --example seed` writes it anew"
        );
        assert_eq!(
            encode(&FORMAT, &golden.decode()).as_ref(),
            Some(&golden.proof),
            "the golden's encoding is its one encoding"
        );
        golden
    })
}

impl DeviceGolden {
    /// The golden proof, decoded.
    pub fn decode(&self) -> MaskedProof<Blake2sM31MerkleHasher> {
        decode(&FORMAT, &self.proof).expect("the golden decodes")
    }

    /// `proof`'s bytes with its interaction PoW ground again over its
    /// commitments, and the verifier's verdict on them: its own nonce kept
    /// when it holds, else the first of the next [`GRIND`] that the
    /// verifier's pre-check passes. `None` when it does not encode.
    pub fn ground(
        &self,
        proof: &MaskedProof<Blake2sM31MerkleHasher>,
    ) -> Option<(Vec<u8>, Result<(), Refusal>)> {
        let bytes = encode(&FORMAT, proof)?;
        // The encoding's first fields, the format and the nonce, as
        // postcard writes them; the rest follows unchanged.
        let head = postcard::to_allocvec(&(FORMAT.number, proof.interaction_pow)).ok()?;
        let rest = bytes.get(head.len()..)?;
        let mut last = None;
        for step in 0..GRIND {
            let nonce = proof.interaction_pow.wrapping_add(step);
            let mut candidate = postcard::to_allocvec(&(FORMAT.number, nonce)).ok()?;
            candidate.extend_from_slice(rest);
            let verdict = self.verifier.verify(&self.io, &candidate);
            if verdict != Err(Refusal::InteractionPow) {
                return Some((candidate, verdict));
            }
            last = Some((candidate, verdict));
        }
        last
    }
}
