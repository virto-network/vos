//! The authentication statement a device proves, as an attestable method:
//! membership of a space without saying which member, and a nullifier.
//!
//! The member's row in a vos-tree (BLAKE2b, salted values, the agent root's
//! format) is checked against the map's root by a one-key multiproof read
//! from its encoding; its value commits to the member's secret; the output
//! is the nullifier for a scope. The root, the scope and the binding are
//! public arguments, so the io-hash states them, as pin I's auth words do.

#![no_std]

extern crate alloc;

use vos_sdk::prelude::*;

pub const TAG_MEMBER: &[u8] = b"vos/auth/member";
pub const TAG_NULLIFIER: &[u8] = b"vos/auth/nullifier";

/// A member's row value: the commitment to its secret.
pub fn member_value(secret: &[u8; 32]) -> [u8; 32] {
    vos_pvm_precompiles::blake2b_hash::<32>(TAG_MEMBER, &[secret])
}

/// The nullifier of `secret` for `scope`.
pub fn nullifier(secret: &[u8; 32], scope: &[u8; 32]) -> [u8; 32] {
    vos_pvm_precompiles::blake2b_hash::<32>(TAG_NULLIFIER, &[secret, scope])
}

/// Whether the member keyed `key` holds the row committing to `secret`
/// under `salt` at `root`, by the encoded multiproof `proof`.
pub fn member_of(
    root: &[u8; 32],
    key: &[u8],
    secret: &[u8; 32],
    salt: &[u8; 16],
    proof: &[u8],
) -> bool {
    let commitment = vos_tree::value_hash(&vos_tree::Blake2b, salt, &member_value(secret));
    vos_tree::verify_encoded(&vos_tree::Blake2b, proof, root, &[(key, Some(commitment))]).is_ok()
}

#[actor]
pub struct Statements {
    count: u64,
}

#[messages]
impl Statements {
    pub fn new() -> Self {
        Self { count: 0 }
    }

    #[msg]
    pub async fn count(&mut self) -> u64 {
        self.count += 1;
        self.count
    }

    /// Membership under `root` of the member keyed `key`, whose row commits
    /// to `secret`: the nullifier for `scope`. A refused path traps.
    #[attestable(gas = 50_000_000)]
    pub fn auth(
        #[public] root: [u8; 32],
        #[public] scope: [u8; 32],
        #[public] binding: [u8; 32],
        key: Vec<u8>,
        secret: [u8; 32],
        salt: [u8; 16],
        proof: Vec<u8>,
    ) -> [u8; 32] {
        let _ = binding;
        assert!(member_of(&root, &key, &secret, &salt, &proof), "a member");
        nullifier(&secret, &scope)
    }
}
