//! Sign registry mutations.
//!
//! Every authority-relevant registry op (`grant_role`, `add_node`,
//! `install`, …) carries an `auth` blob the registry actor verifies
//! at handler time and re-verifies on every peer's causal replay.
//! The signer is the operator's libp2p identity key — held by the
//! CLI on a `vosx space …` command, and by the daemon at boot for
//! the genesis (`space new`) and manifest-reconcile paths.
//!
//! The canonical bytes are built by the shared
//! [`vos::registry::canonical_op_bytes`], so the signer and the
//! verifier stay in lockstep without re-encoding the wire `Msg`.

use libp2p::identity::Keypair;
use vos::registry::{OP_SIG_LEN, canonical_op_bytes, pack_auth};

/// Build the `auth` blob for a signed registry op: the signer's
/// PeerId bytes followed by an ed25519 signature over the op's
/// canonical bytes (`domain || op || fields`).
///
/// `fields` must match — byte for byte, in order — what the
/// corresponding registry handler passes to `canonical_op_bytes`.
pub fn op_auth(keypair: &Keypair, op: &str, fields: &[&[u8]]) -> anyhow::Result<Vec<u8>> {
    let canonical = canonical_op_bytes(op, fields);
    let sig: [u8; OP_SIG_LEN] = keypair
        .sign(&canonical)
        .map_err(|e| anyhow::anyhow!("sign registry op '{op}': {e}"))?
        .as_slice()
        .try_into()
        .map_err(|_| {
            anyhow::anyhow!("registry op '{op}': expected a {OP_SIG_LEN}-byte ed25519 signature")
        })?;
    let signer = libp2p::PeerId::from(keypair.public()).to_bytes();
    Ok(pack_auth(&signer, &sig))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos::registry::ed25519_pubkey_from_peer_id;
    // `verify_op_sig` (ed25519) deliberately stays in the actor crate so
    // its `ed25519-dalek` dep never reaches `vos`; this interop test is
    // the only reason `space-registry` remains a vosx *dev*-dependency.
    use space_registry::verify_op_sig;

    /// The make-or-break interop: a signature produced by a libp2p
    /// `Keypair` (the operator's CLI identity) must verify under the
    /// registry actor's `verify_op_sig`, and the PeerId we ship in the
    /// auth blob must yield the same ed25519 key the actor extracts.
    #[test]
    fn op_auth_verifies_under_the_registry() {
        let kp = Keypair::generate_ed25519();
        let peer = libp2p::PeerId::from(kp.public()).to_bytes();
        let fields: [&[u8]; 2] = [&[1u8, 2, 3], &[3u8]];

        let auth = op_auth(&kp, "grant_role", &fields).expect("sign");

        // Split exactly as the actor's `unpack_auth` does.
        let (signer, sig) = auth.split_at(auth.len() - OP_SIG_LEN);
        assert_eq!(signer, peer.as_slice(), "auth carries the operator PeerId");
        let mut sig_arr = [0u8; OP_SIG_LEN];
        sig_arr.copy_from_slice(sig);

        let canonical = canonical_op_bytes("grant_role", &fields);
        assert!(
            verify_op_sig(signer, &canonical, &sig_arr),
            "libp2p-produced signature verifies under the registry",
        );
        assert!(
            ed25519_pubkey_from_peer_id(signer).is_some(),
            "the PeerId is a recognised ed25519 identity",
        );

        // A signature is not transferable to a different op.
        let other = canonical_op_bytes("revoke_role", &[&[1u8, 2, 3]]);
        assert!(!verify_op_sig(signer, &other, &sig_arr));
    }
}
