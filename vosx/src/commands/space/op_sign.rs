//! Sign registry mutations.
//!
//! Every authority-relevant registry op (`grant_role`, `add_node`,
//! `install`, …) carries an `auth` blob the registry actor verifies
//! at handler time and re-verifies on every peer's causal replay.
//! The signer is the operator's libp2p identity key — held by the
//! CLI on a `vosx space …` command, and by the daemon at boot for
//! the genesis (`space new`) and recipe-reconcile paths.
//!
//! The canonical bytes are built by the shared
//! [`vos::registry::registry_mutation_signed_bytes`], so the signer and the
//! verifier stay in lockstep without re-encoding the wire `Msg`.

use libp2p::identity::Keypair;
use vos::registry::{OP_SIG_LEN, pack_auth, registry_mutation_signed_bytes};

/// Build the `auth` blob for a signed registry op: the signer's
/// PeerId bytes followed by an ed25519 signature over the op's
/// canonical bytes (`domain || schema || space_id || op || fields`).
///
/// `fields` must match — byte for byte, in order — what the
/// corresponding registry handler passes to
/// `registry_mutation_signed_bytes`.
pub fn op_auth(
    keypair: &Keypair,
    space_id: &[u8; 32],
    op: &str,
    fields: &[&[u8]],
) -> anyhow::Result<Vec<u8>> {
    if *space_id == [0; 32] {
        anyhow::bail!("registry mutation space_id must be nonzero");
    }
    let canonical = registry_mutation_signed_bytes(space_id, op, fields);
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
        let space_id = [0x5a; 32];
        let fields: [&[u8]; 2] = [&[1u8, 2, 3], &[3u8]];

        let auth = op_auth(&kp, &space_id, "grant_role", &fields).expect("sign");

        // Split exactly as the actor's `unpack_auth` does.
        let (signer, sig) = auth.split_at(auth.len() - OP_SIG_LEN);
        assert_eq!(signer, peer.as_slice(), "auth carries the operator PeerId");
        let mut sig_arr = [0u8; OP_SIG_LEN];
        sig_arr.copy_from_slice(sig);

        let canonical = registry_mutation_signed_bytes(&space_id, "grant_role", &fields);
        assert!(
            verify_op_sig(signer, &canonical, &sig_arr),
            "libp2p-produced signature verifies under the registry",
        );
        assert!(
            ed25519_pubkey_from_peer_id(signer).is_some(),
            "the PeerId is a recognised ed25519 identity",
        );

        // A signature is not transferable to a different op.
        let other = registry_mutation_signed_bytes(&space_id, "revoke_role", &[&[1u8, 2, 3]]);
        assert!(!verify_op_sig(signer, &other, &sig_arr));

        let sibling = registry_mutation_signed_bytes(&[0x6b; 32], "grant_role", &fields);
        assert!(!verify_op_sig(signer, &sibling, &sig_arr));
    }
}
