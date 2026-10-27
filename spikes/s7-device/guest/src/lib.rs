//! The authentication statement a device proves, as attestable methods:
//! membership of a space without saying which member, and a nullifier.
//!
//! - `auth`, over a vos-tree (BLAKE2b, salted values, the agent root's
//!   format): the member's row checked against the map's root by a one-key
//!   multiproof read from its encoding; its value commits to the member's
//!   secret; the output is the nullifier for a scope. The root, the scope
//!   and the binding are public arguments, so the io-hash states them, as
//!   pin I's auth words do.
//! - `auth_p2`, over the credential actor's Poseidon2 tree through the
//!   `0x402` call (`proving.md` §8, S21): pin J's device kernel, its public
//!   arguments auth's `CredentialPublic` (the kind byte, then `map_root`,
//!   `scope`, `nullifier` and `binding`), its output empty; the path walked
//!   with selects, 36 compressions.

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

/// A digest's eight words, little-endian; a word at or above p traps in the
/// call that takes it.
fn words(digest: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| u32::from_le_bytes(digest[4 * i..4 * i + 4].try_into().unwrap()))
}

/// The root `secret`'s leaf gives at `slot` by `siblings` (32 digests from
/// the leaf's level up), and the
/// nullifier for `scope`: the leaf `C(T(leaf), C(T(member), s))`, one
/// compression a level with its children ordered by the slot's bit through
/// a mask, never a branch; the nullifier `C(C(T(nf), s), scope)`.
pub fn auth_p2_words(
    secret: &[u8; 32],
    slot: u32,
    siblings: &[u8; 1024],
    scope: &[u8; 32],
) -> ([u32; 8], [u32; 8]) {
    use vos_wire::credentials::{Tag, compress};
    let s = words(secret);
    let mut node = compress(&Tag::Leaf.block(), &compress(&Tag::Member.block(), &s));
    for (level, sibling) in siblings.chunks_exact(32).enumerate() {
        let sibling = words(sibling.try_into().unwrap());
        let right = 0u32.wrapping_sub((slot >> level) & 1);
        let left: [u32; 8] = core::array::from_fn(|i| (sibling[i] & right) | (node[i] & !right));
        let other: [u32; 8] = core::array::from_fn(|i| (node[i] & right) | (sibling[i] & !right));
        node = compress(&left, &other);
    }
    let key = compress(&Tag::Nf.block(), &s);
    (node, compress(&key, &words(scope)))
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

    /// Auth over the Poseidon2 tree: `secret`'s leaf at `slot` under
    /// `map_root` by `siblings`, and `nullifier` its nullifier for `scope`.
    /// Anything else traps.
    #[attestable(gas = 50_000_000)]
    #[allow(clippy::too_many_arguments)]
    pub fn auth_p2(
        #[public] kind: u8,
        #[public] map_root: [u8; 32],
        #[public] scope: [u8; 32],
        #[public] nullifier: [u8; 32],
        #[public] binding: [u8; 32],
        secret: [u8; 32],
        slot: u32,
        siblings: [u8; 1024],
    ) {
        let _ = binding;
        let (root, derived) = auth_p2_words(&secret, slot, &siblings, &scope);
        let matched = u32::from(kind == 0)
            & u32::from(root == words(&map_root))
            & u32::from(derived == words(&nullifier));
        assert!(matched == 1, "a member");
    }
}
